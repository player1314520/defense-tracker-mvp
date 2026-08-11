-- Allow the operator-provisioned first Owner to publish only the envelope for
-- the exact active desktop device and JWT session recorded by bootstrap.
begin;

create or replace function public.put_mvp_first_owner_key_envelope(
    p_key_version integer,
    p_ephemeral_public_key text,
    p_envelope_nonce text,
    p_envelope_ciphertext text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    caller_session text := private.current_session_id();
    binding private.device_sessions%rowtype;
    marker private.mvp_owner_bootstrap%rowtype;
    existing public.key_envelopes%rowtype;
    organization_count bigint;
    envelope_count bigint;
    organization_key_version integer;
    decoded_ephemeral_public_key bytea;
    decoded_envelope_nonce bytea;
    decoded_envelope_ciphertext bytea;
begin
    if actor is null or caller_session is null then
        raise exception 'active authenticated session required'
            using errcode = '42501';
    end if;
    if p_key_version is null
       or p_key_version < 1
       or p_ephemeral_public_key is null
       or length(p_ephemeral_public_key) <> 87
       or p_ephemeral_public_key !~ '^[A-Za-z0-9_-]+$'
       or p_envelope_nonce is null
       or length(p_envelope_nonce) <> 16
       or p_envelope_nonce !~ '^[A-Za-z0-9_-]+$'
       or p_envelope_ciphertext is null
       or length(p_envelope_ciphertext) <> 64
       or p_envelope_ciphertext !~ '^[A-Za-z0-9_-]+$' then
        raise exception 'invalid first owner envelope';
    end if;

    begin
        decoded_ephemeral_public_key := private.decode_base64url(
            p_ephemeral_public_key
        );
        decoded_envelope_nonce := private.decode_base64url(
            p_envelope_nonce
        );
        decoded_envelope_ciphertext := private.decode_base64url(
            p_envelope_ciphertext
        );
    exception when others then
        raise exception 'invalid first owner envelope';
    end;
    if octet_length(decoded_ephemeral_public_key) <> 65
       or pg_catalog.get_byte(decoded_ephemeral_public_key,0) <> 4
       or octet_length(decoded_envelope_nonce) <> 12
       or octet_length(decoded_envelope_ciphertext) <> 48
       or private.encode_base64url(decoded_ephemeral_public_key)
          <> p_ephemeral_public_key
       or private.encode_base64url(decoded_envelope_nonce)
          <> p_envelope_nonce
       or private.encode_base64url(decoded_envelope_ciphertext)
          <> p_envelope_ciphertext then
        raise exception 'invalid first owner envelope';
    end if;

    perform pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'defense-tracker:mvp:first-owner-envelope',0
        )
    );

    perform s.id
    from auth.sessions s
    where s.id::text = caller_session
      and s.user_id = actor
    for share;
    if not found then
        raise exception 'active authenticated session required'
            using errcode = '42501';
    end if;

    select b.* into marker
    from private.mvp_owner_bootstrap b
    where b.singleton
    for update;
    if not found
       or marker.status <> 'finalized'
       or marker.finalized_at is null
       or marker.payload_sha256 is null
       or marker.auth_user_id is distinct from actor
       or marker.organization_id is null
       or marker.device_id is null then
        raise exception 'finalized first owner bootstrap required'
            using errcode = '42501';
    end if;

    select count(*) into organization_count from public.organizations;
    if organization_count <> 1 then
        raise exception 'single MVP organization required'
            using errcode = '42501';
    end if;
    select o.key_version into organization_key_version
    from public.organizations o
    where o.id = marker.organization_id
      and o.created_by = actor
      and o.mvp_singleton
    for update;
    if not found
       or p_key_version is distinct from organization_key_version then
        raise exception 'organization key version mismatch'
            using errcode = '42501';
    end if;

    perform m.user_id
    from public.memberships m
    where m.organization_id = marker.organization_id
      and m.user_id = actor
      and m.role = 'owner'
      and m.status = 'active'
    for share;
    if not found then
        raise exception 'active first owner membership required'
            using errcode = '42501';
    end if;

    perform d.id
    from public.devices d
    where d.organization_id = marker.organization_id
      and d.id = marker.device_id
      and d.user_id = actor
      and d.status = 'active'
      and d.device_kind = 'desktop'
      and d.key_algorithm = 'p256'
      and octet_length(d.public_key) = 65
      and pg_catalog.get_byte(d.public_key,0) = 4
    for share;
    if not found then
        raise exception 'active bootstrap desktop device required'
            using errcode = '42501';
    end if;

    -- Keep the organization-before-session lock order used by
    -- bind_device_session and pair_device so concurrent retries cannot form
    -- a lock cycle.
    select ds.* into binding
    from private.device_sessions ds
    where ds.session_id = caller_session
      and ds.organization_id = marker.organization_id
      and ds.device_id = marker.device_id
      and ds.user_id = actor
      and ds.status = 'active'
      and ds.revoked_at is null
    for update;
    if not found
       or marker.organization_id is distinct from binding.organization_id
       or marker.device_id is distinct from binding.device_id then
        raise exception 'active bootstrap device session required'
            using errcode = '42501';
    end if;

    select count(*) into envelope_count
    from public.key_envelopes e
    where e.organization_id = binding.organization_id;
    if envelope_count not in (0,1) then
        raise exception 'first owner envelope state conflict'
            using errcode = '23505';
    end if;

    select e.* into existing
    from public.key_envelopes e
    where e.organization_id = binding.organization_id
      and e.device_id = binding.device_id
      and e.key_version = p_key_version
    for update;
    if found then
        if existing.key_algorithm = 'p256'
           and existing.ephemeral_public_key = decoded_ephemeral_public_key
           and existing.nonce = decoded_envelope_nonce
           and existing.ciphertext = decoded_envelope_ciphertext then
            return jsonb_build_object(
                'status','ready',
                'organization_id',binding.organization_id,
                'device_id',binding.device_id,
                'key_version',p_key_version
            );
        end if;
        raise exception 'first owner envelope conflict'
            using errcode = '23505';
    end if;
    if envelope_count <> 0 then
        raise exception 'first owner envelope conflict'
            using errcode = '23505';
    end if;

    insert into public.key_envelopes(
        organization_id,device_id,key_version,key_algorithm,
        ephemeral_public_key,nonce,ciphertext
    ) values (
        binding.organization_id,binding.device_id,p_key_version,'p256',
        decoded_ephemeral_public_key,decoded_envelope_nonce,
        decoded_envelope_ciphertext
    );

    return jsonb_build_object(
        'status','ready',
        'organization_id',binding.organization_id,
        'device_id',binding.device_id,
        'key_version',p_key_version
    );
end;
$$;

revoke all on function public.put_mvp_first_owner_key_envelope(integer,text,text,text)
    from public, anon, authenticated, service_role;
grant execute on function public.put_mvp_first_owner_key_envelope(integer,text,text,text)
    to authenticated;

comment on function public.put_mvp_first_owner_key_envelope(integer,text,text,text) is
    'One-time idempotent P-256 envelope publication for the finalized MVP first Owner bootstrap device.';

commit;
