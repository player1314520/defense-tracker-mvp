-- Persist only client-encrypted AI credentials and per-device wrapped data
-- keys.  Every RPC derives the user and desktop device from the JWT session.
begin;

create table if not exists private.user_ai_credentials (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null
        references public.organizations(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    provider text not null check (
        provider in ('deepseek','zhipu','moonshot')
    ),
    model_id text not null,
    credential_version integer not null check (
        credential_version between 1 and 2147483647
    ),
    ciphertext bytea not null check (
        octet_length(ciphertext) between 17 and 4112
    ),
    nonce bytea not null check (octet_length(nonce) = 12),
    core_sha256 text not null check (core_sha256 ~ '^[0-9a-f]{64}$'),
    created_by_device uuid not null,
    updated_by_device uuid not null,
    created_at timestamptz not null default statement_timestamp(),
    updated_at timestamptz not null default statement_timestamp(),
    unique (user_id,provider),
    unique (organization_id,id,user_id),
    foreign key (organization_id,created_by_device)
        references public.devices(organization_id,id),
    foreign key (organization_id,updated_by_device)
        references public.devices(organization_id,id),
    check (
        (provider = 'deepseek' and model_id in (
            'deepseek-v4-flash','deepseek-v4-pro'
        ))
        or (provider = 'zhipu' and model_id in (
            'glm-5.2','glm-5-turbo'
        ))
        or (provider = 'moonshot' and model_id in (
            'kimi-k3','kimi-k2.6'
        ))
    )
);

create table if not exists private.user_ai_key_envelopes (
    credential_id uuid not null,
    organization_id uuid not null,
    user_id uuid not null,
    credential_version integer not null check (
        credential_version between 1 and 2147483647
    ),
    device_id uuid not null,
    key_algorithm text not null check (key_algorithm = 'p256'),
    ephemeral_public_key bytea not null check (
        octet_length(ephemeral_public_key) = 65
    ),
    nonce bytea not null check (octet_length(nonce) = 12),
    ciphertext bytea not null check (octet_length(ciphertext) = 48),
    created_at timestamptz not null default statement_timestamp(),
    primary key (credential_id,credential_version,device_id),
    foreign key (organization_id,credential_id,user_id)
        references private.user_ai_credentials(organization_id,id,user_id)
        on delete cascade,
    foreign key (organization_id,device_id)
        references public.devices(organization_id,id) on delete cascade
);

create index if not exists user_ai_credentials_context_idx
    on private.user_ai_credentials(organization_id,user_id,provider);
create index if not exists user_ai_key_envelopes_device_idx
    on private.user_ai_key_envelopes(organization_id,device_id);

revoke all on table private.user_ai_credentials
    from public, anon, authenticated, service_role;
revoke all on table private.user_ai_key_envelopes
    from public, anon, authenticated, service_role;

create or replace function private.current_active_desktop_context()
returns table (
    organization_id uuid,
    device_id uuid,
    user_id uuid
)
language sql
stable
security definer
set search_path = ''
as $$
    select ds.organization_id,ds.device_id,ds.user_id
    from private.device_sessions ds
    join public.devices d
      on d.organization_id = ds.organization_id
     and d.id = ds.device_id
     and d.user_id = ds.user_id
    join public.memberships m
      on m.organization_id = ds.organization_id
     and m.user_id = ds.user_id
     and m.status = 'active'
    where ds.session_id = private.current_session_id()
      and ds.user_id = (select auth.uid())
      and ds.status = 'active'
      and ds.revoked_at is null
      and d.user_id = (select auth.uid())
      and d.status = 'active'
      and d.device_kind = 'desktop'
      and d.key_algorithm = 'p256'
    limit 1;
$$;

create or replace function public.list_user_ai_credential_devices()
returns table (
    device_id uuid,
    user_id uuid,
    status text,
    device_kind text,
    key_algorithm text,
    public_key text
)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
    context_org uuid;
    context_device uuid;
    context_user uuid;
begin
    select c.organization_id,c.device_id,c.user_id
      into context_org,context_device,context_user
    from private.current_active_desktop_context() c;
    if context_org is null then
        raise exception 'active desktop device session required'
            using errcode = '42501';
    end if;

    return query
    select
        d.id,d.user_id,d.status,d.device_kind,d.key_algorithm,
        private.encode_base64url(d.public_key)
    from public.devices d
    where d.organization_id = context_org
      and d.user_id = context_user
      and d.status = 'active'
      and d.device_kind = 'desktop'
      and d.key_algorithm = 'p256'
    order by (d.id = context_device) desc,d.id
    limit 32;
end;
$$;

create or replace function public.put_user_ai_credential(
    credential jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    context_org uuid;
    context_device uuid;
    context_user uuid;
    provider_name text;
    selected_model text;
    supplied_version integer;
    decoded_ciphertext bytea;
    decoded_nonce bytea;
    core_hash text;
    existing private.user_ai_credentials%rowtype;
    credential_id uuid;
    envelope jsonb;
    envelope_device uuid;
    envelope_version integer;
    decoded_ephemeral_public_key bytea;
    decoded_envelope_nonce bytea;
    decoded_envelope_ciphertext bytea;
    current_device_included boolean := false;
    existing_envelope private.user_ai_key_envelopes%rowtype;
    active_device_count integer;
begin
    select c.organization_id,c.device_id,c.user_id
      into context_org,context_device,context_user
    from private.current_active_desktop_context() c;
    if context_org is null then
        raise exception 'active desktop device session required'
            using errcode = '42501';
    end if;

    if credential is null or jsonb_typeof(credential) <> 'object'
       or (select count(*) from jsonb_object_keys(credential)) <> 6
       or not (
           credential ?& array[
               'provider','model_id','credential_version',
               'ciphertext','nonce','device_envelopes'
           ]::text[]
       )
       or jsonb_typeof(credential->'provider') <> 'string'
       or jsonb_typeof(credential->'model_id') <> 'string'
       or jsonb_typeof(credential->'ciphertext') <> 'string'
       or jsonb_typeof(credential->'nonce') <> 'string' then
        raise exception 'invalid encrypted credential payload';
    end if;
    provider_name := credential->>'provider';
    selected_model := credential->>'model_id';
    if not (
        (provider_name = 'deepseek' and selected_model in (
            'deepseek-v4-flash','deepseek-v4-pro'
        ))
        or (provider_name = 'zhipu' and selected_model in (
            'glm-5.2','glm-5-turbo'
        ))
        or (provider_name = 'moonshot' and selected_model in (
            'kimi-k3','kimi-k2.6'
        ))
    ) then
        raise exception 'unsupported provider or model';
    end if;
    if jsonb_typeof(credential->'credential_version') <> 'number'
       or credential->>'credential_version' !~ '^[1-9][0-9]{0,9}$' then
        raise exception 'invalid credential version';
    end if;
    begin
        supplied_version := (credential->>'credential_version')::integer;
    exception when others then
        raise exception 'invalid credential version';
    end;
    if supplied_version < 1 then
        raise exception 'invalid credential version';
    end if;

    if length(credential->>'ciphertext') < 23
       or length(credential->>'ciphertext') > 5483
       or length(credential->>'ciphertext') % 4 = 1
       or credential->>'ciphertext' !~ '^[A-Za-z0-9_-]+$'
       or length(credential->>'nonce') <> 16
       or credential->>'nonce' !~ '^[A-Za-z0-9_-]+$' then
        raise exception 'invalid encrypted credential payload';
    end if;

    begin
        decoded_ciphertext := private.decode_base64url(
            credential->>'ciphertext'
        );
        decoded_nonce := private.decode_base64url(credential->>'nonce');
    exception when others then
        raise exception 'invalid encrypted credential payload';
    end;
    if octet_length(decoded_ciphertext) not between 17 and 4112
       or octet_length(decoded_nonce) <> 12
       or private.encode_base64url(decoded_ciphertext)
          <> credential->>'ciphertext'
       or private.encode_base64url(decoded_nonce)
          <> credential->>'nonce' then
        raise exception 'invalid encrypted credential payload';
    end if;
    if jsonb_typeof(credential->'device_envelopes') <> 'array'
       or jsonb_array_length(credential->'device_envelopes') < 1
       or jsonb_array_length(credential->'device_envelopes') > 32 then
        raise exception 'device envelope count must be between 1 and 32';
    end if;

    core_hash := pg_catalog.encode(
        extensions.digest(
            pg_catalog.convert_to(
                jsonb_build_object(
                    'provider',provider_name,
                    'model_id',selected_model,
                    'credential_version',supplied_version,
                    'ciphertext',credential->>'ciphertext',
                    'nonce',credential->>'nonce'
                )::text,
                'UTF8'
            ),
            'sha256'
        ),
        'hex'
    );

    -- Serialize the empty-row case as well as rotations. A row lock alone
    -- cannot fence two concurrent first writes for the same provider.
    perform pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            context_user::text || ':' || provider_name,
            0
        )
    );

    select c.* into existing
    from private.user_ai_credentials c
    where c.user_id = context_user
      and c.provider = provider_name
    for update;
    if found then
        if supplied_version = existing.credential_version then
            if existing.core_sha256 <> core_hash then
                raise exception 'credential version conflict';
            end if;
            credential_id := existing.id;
        elsif supplied_version <> existing.credential_version + 1 then
            raise exception 'credential version conflict';
        else
            credential_id := existing.id;
        end if;
    else
        if supplied_version <> 1 then
            raise exception 'first credential version must be 1';
        end if;
        credential_id := gen_random_uuid();
    end if;

    -- Validate every target before changing the credential or envelope set.
    for envelope in
        select value from jsonb_array_elements(
            credential->'device_envelopes'
        )
    loop
        if jsonb_typeof(envelope) <> 'object'
           or (select count(*) from jsonb_object_keys(envelope)) <> 6
           or not (
               envelope ?& array[
                   'credential_version','device_id','key_algorithm',
                   'ephemeral_public_key','nonce','ciphertext'
               ]::text[]
           )
           or jsonb_typeof(envelope->'credential_version') <> 'number'
           or jsonb_typeof(envelope->'device_id') <> 'string'
           or jsonb_typeof(envelope->'key_algorithm') <> 'string'
           or jsonb_typeof(envelope->'ephemeral_public_key') <> 'string'
           or jsonb_typeof(envelope->'nonce') <> 'string'
           or jsonb_typeof(envelope->'ciphertext') <> 'string'
           or envelope->>'key_algorithm' <> 'p256'
           or envelope->>'credential_version' !~ '^[1-9][0-9]{0,9}$'
           or length(envelope->>'ephemeral_public_key') <> 87
           or envelope->>'ephemeral_public_key'
              !~ '^[A-Za-z0-9_-]+$'
           or length(envelope->>'nonce') <> 16
           or envelope->>'nonce' !~ '^[A-Za-z0-9_-]+$'
           or length(envelope->>'ciphertext') <> 64
           or envelope->>'ciphertext' !~ '^[A-Za-z0-9_-]+$' then
            raise exception 'invalid device envelope';
        end if;
        begin
            envelope_device := (envelope->>'device_id')::uuid;
            envelope_version :=
                (envelope->>'credential_version')::integer;
            decoded_ephemeral_public_key := private.decode_base64url(
                envelope->>'ephemeral_public_key'
            );
            decoded_envelope_nonce := private.decode_base64url(
                envelope->>'nonce'
            );
            decoded_envelope_ciphertext := private.decode_base64url(
                envelope->>'ciphertext'
            );
        exception when others then
            raise exception 'invalid device envelope';
        end;
        if envelope_version <> supplied_version
           or octet_length(decoded_ephemeral_public_key) <> 65
           or octet_length(decoded_envelope_nonce) <> 12
           or octet_length(decoded_envelope_ciphertext) <> 48
           or private.encode_base64url(decoded_ephemeral_public_key)
              <> envelope->>'ephemeral_public_key'
           or private.encode_base64url(decoded_envelope_nonce)
              <> envelope->>'nonce'
           or private.encode_base64url(decoded_envelope_ciphertext)
              <> envelope->>'ciphertext' then
            raise exception 'invalid device envelope';
        end if;
        perform d.id
        from public.devices d
        where d.organization_id = context_org
          and d.id = envelope_device
          and d.user_id = context_user
          and d.status = 'active'
          and d.device_kind = 'desktop'
          and d.key_algorithm = 'p256'
        for share;
        if not found then
            raise exception 'envelope target is not an active desktop device';
        end if;
        if envelope_device = context_device then
            current_device_included := true;
        end if;
    end loop;
    if not current_device_included then
        raise exception 'current desktop envelope required';
    end if;

    if existing.id is null then
        insert into private.user_ai_credentials(
            id,organization_id,user_id,provider,model_id,
            credential_version,ciphertext,nonce,core_sha256,
            created_by_device,updated_by_device
        ) values (
            credential_id,context_org,context_user,provider_name,
            selected_model,supplied_version,decoded_ciphertext,
            decoded_nonce,core_hash,context_device,context_device
        );
    elsif supplied_version = existing.credential_version + 1 then
        update private.user_ai_credentials
           set model_id = selected_model,
               credential_version = supplied_version,
               ciphertext = decoded_ciphertext,
               nonce = decoded_nonce,
               core_sha256 = core_hash,
               updated_by_device = context_device,
               updated_at = statement_timestamp()
         where id = credential_id;
        delete from private.user_ai_key_envelopes e
        where e.credential_id = credential_id;
    end if;

    for envelope in
        select value from jsonb_array_elements(
            credential->'device_envelopes'
        )
    loop
        envelope_device := (envelope->>'device_id')::uuid;
        decoded_ephemeral_public_key := private.decode_base64url(
            envelope->>'ephemeral_public_key'
        );
        decoded_envelope_nonce := private.decode_base64url(
            envelope->>'nonce'
        );
        decoded_envelope_ciphertext := private.decode_base64url(
            envelope->>'ciphertext'
        );

        select e.* into existing_envelope
        from private.user_ai_key_envelopes e
        where e.credential_id = credential_id
          and e.credential_version = supplied_version
          and e.device_id = envelope_device
        for update;
        if found then
            if existing_envelope.ephemeral_public_key
                   is distinct from decoded_ephemeral_public_key
               or existing_envelope.nonce
                   is distinct from decoded_envelope_nonce
               or existing_envelope.ciphertext
                   is distinct from decoded_envelope_ciphertext then
                raise exception 'credential envelope conflict';
            end if;
        else
            insert into private.user_ai_key_envelopes(
                credential_id,organization_id,user_id,credential_version,
                device_id,key_algorithm,ephemeral_public_key,nonce,ciphertext
            ) values (
                credential_id,context_org,context_user,supplied_version,
                envelope_device,'p256',decoded_ephemeral_public_key,
                decoded_envelope_nonce,decoded_envelope_ciphertext
            );
        end if;
    end loop;

    update private.user_ai_credentials
       set updated_by_device = context_device,
           updated_at = statement_timestamp()
     where id = credential_id;
    select count(*) into active_device_count
    from private.user_ai_key_envelopes e
    where e.credential_id = credential_id
      and e.credential_version = supplied_version;
    return jsonb_build_object(
        'provider',provider_name,
        'model_id',selected_model,
        'credential_version',supplied_version,
        'device_count',active_device_count
    );
end;
$$;

create or replace function public.get_user_ai_credential(
    provider_name text
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
    context_org uuid;
    context_device uuid;
    context_user uuid;
    target private.user_ai_credentials%rowtype;
    envelope private.user_ai_key_envelopes%rowtype;
begin
    select c.organization_id,c.device_id,c.user_id
      into context_org,context_device,context_user
    from private.current_active_desktop_context() c;
    if context_org is null then
        raise exception 'active desktop device session required'
            using errcode = '42501';
    end if;
    if provider_name not in ('deepseek','zhipu','moonshot') then
        raise exception 'unsupported provider';
    end if;
    select c.* into target
    from private.user_ai_credentials c
    where c.organization_id = context_org
      and c.user_id = context_user
      and c.provider = provider_name;
    if not found then
        return null;
    end if;
    select e.* into envelope
    from private.user_ai_key_envelopes e
    where e.credential_id = target.id
      and e.credential_version = target.credential_version
      and e.device_id = context_device;
    if not found then
        raise exception 'credential is not wrapped for current device'
            using errcode = '42501';
    end if;
    return jsonb_build_object(
        'provider',target.provider,
        'model_id',target.model_id,
        'credential_version',target.credential_version,
        'ciphertext',private.encode_base64url(target.ciphertext),
        'nonce',private.encode_base64url(target.nonce),
        'device_envelopes',jsonb_build_array(jsonb_build_object(
            'credential_version',envelope.credential_version,
            'device_id',envelope.device_id,
            'key_algorithm',envelope.key_algorithm,
            'ephemeral_public_key',
                private.encode_base64url(envelope.ephemeral_public_key),
            'nonce',private.encode_base64url(envelope.nonce),
            'ciphertext',private.encode_base64url(envelope.ciphertext)
        ))
    );
end;
$$;

create or replace function public.list_user_ai_credentials()
returns table (
    provider text,
    model_id text,
    credential_version integer,
    updated_at timestamptz,
    device_count bigint
)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
    context_org uuid;
    context_device uuid;
    context_user uuid;
begin
    select c.organization_id,c.device_id,c.user_id
      into context_org,context_device,context_user
    from private.current_active_desktop_context() c;
    if context_org is null then
        raise exception 'active desktop device session required'
            using errcode = '42501';
    end if;
    return query
    select
        c.provider,c.model_id,c.credential_version,c.updated_at,
        count(e.device_id)
    from private.user_ai_credentials c
    left join private.user_ai_key_envelopes e
      on e.credential_id = c.id
     and e.credential_version = c.credential_version
    where c.organization_id = context_org
      and c.user_id = context_user
    group by c.id,c.provider,c.model_id,c.credential_version,c.updated_at
    order by c.provider;
end;
$$;

create or replace function public.delete_user_ai_credential(
    provider_name text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    context_org uuid;
    context_device uuid;
    context_user uuid;
    removed integer;
begin
    select c.organization_id,c.device_id,c.user_id
      into context_org,context_device,context_user
    from private.current_active_desktop_context() c;
    if context_org is null then
        raise exception 'active desktop device session required'
            using errcode = '42501';
    end if;
    if provider_name not in ('deepseek','zhipu','moonshot') then
        raise exception 'unsupported provider';
    end if;
    delete from private.user_ai_credentials c
    where c.organization_id = context_org
      and c.user_id = context_user
      and c.provider = provider_name;
    get diagnostics removed = row_count;
    return jsonb_build_object('deleted',removed = 1);
end;
$$;

create or replace function private.remove_revoked_ai_key_envelopes()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if new.status = 'revoked' and old.status is distinct from new.status then
        delete from private.user_ai_key_envelopes e
        where e.organization_id = new.organization_id
          and e.device_id = new.id;
    end if;
    return new;
end;
$$;

drop trigger if exists remove_revoked_ai_key_envelopes on public.devices;
create trigger remove_revoked_ai_key_envelopes
after update of status on public.devices
for each row execute function private.remove_revoked_ai_key_envelopes();

revoke all on function private.current_active_desktop_context()
    from public, anon, authenticated, service_role;
revoke all on function private.remove_revoked_ai_key_envelopes()
    from public, anon, authenticated, service_role;

revoke all on function public.put_user_ai_credential(jsonb)
    from public, anon, authenticated;
revoke all on function public.get_user_ai_credential(text)
    from public, anon, authenticated;
revoke all on function public.list_user_ai_credentials()
    from public, anon, authenticated;
revoke all on function public.delete_user_ai_credential(text)
    from public, anon, authenticated;
revoke all on function public.list_user_ai_credential_devices()
    from public, anon, authenticated;

grant execute on function public.put_user_ai_credential(jsonb)
    to authenticated;
grant execute on function public.get_user_ai_credential(text)
    to authenticated;
grant execute on function public.list_user_ai_credentials()
    to authenticated;
grant execute on function public.delete_user_ai_credential(text)
    to authenticated;
grant execute on function public.list_user_ai_credential_devices()
    to authenticated;

comment on table private.user_ai_credentials is
    'Client-encrypted credential ciphertext; plaintext is never sent.';
comment on table private.user_ai_key_envelopes is
    'P-256 wrapped data key per active desktop device.';

commit;
