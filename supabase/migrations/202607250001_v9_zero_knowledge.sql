-- V9 zero-knowledge cloud schema.
-- Business bodies and files are encrypted by an unlocked client before upload.
begin;

create extension if not exists pgcrypto;
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists public.organizations (
    id uuid primary key default gen_random_uuid(),
    name_ciphertext bytea not null,
    name_nonce bytea not null,
    key_version integer not null default 1 check (key_version > 0),
    created_by uuid not null references auth.users(id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists public.memberships (
    organization_id uuid not null references public.organizations(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    role text not null check (
        role in ('owner','admin','collector','analyst','editor','approver')
    ),
    status text not null default 'active' check (status in ('active','revoked')),
    created_at timestamptz not null default now(),
    revoked_at timestamptz,
    primary key (organization_id, user_id)
);

create table if not exists public.devices (
    id uuid not null,
    organization_id uuid not null references public.organizations(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    key_algorithm text not null check (key_algorithm in ('x25519','p256')),
    public_key bytea not null,
    name_ciphertext bytea not null,
    name_nonce bytea not null,
    status text not null default 'active' check (
        status in ('pending','active','revoked')
    ),
    created_at timestamptz not null default now(),
    revoked_at timestamptz,
    primary key (organization_id, id),
    unique (organization_id, id)
);

create table if not exists public.key_envelopes (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    device_id uuid not null,
    key_version integer not null check (key_version > 0),
    key_algorithm text not null check (key_algorithm in ('x25519','p256')),
    ephemeral_public_key bytea not null,
    nonce bytea not null,
    ciphertext bytea not null,
    created_at timestamptz not null default now(),
    foreign key (organization_id, device_id)
        references public.devices(organization_id, id) on delete cascade,
    unique (organization_id, device_id, key_version)
);

create table if not exists public.recovery_envelopes (
    organization_id uuid not null references public.organizations(id) on delete cascade,
    key_version integer not null check (key_version > 0),
    salt bytea not null,
    nonce bytea not null,
    ciphertext bytea not null,
    created_at timestamptz not null default now(),
    primary key (organization_id, key_version)
);

create table if not exists public.record_heads (
    organization_id uuid not null references public.organizations(id) on delete cascade,
    record_id uuid not null,
    record_type text not null check (
        record_type in (
            'source','evidence','claim','entity','relation','geo_event',
            'alert_rule','alert','case','job','scenario','document',
            'publication_item','audit_event'
        )
    ),
    head_version_id uuid,
    logical_version bigint not null default 0 check (logical_version >= 0),
    deleted boolean not null default false,
    updated_at timestamptz not null default now(),
    primary key (organization_id, record_id),
    unique (organization_id, record_id)
);

create table if not exists public.record_versions (
    organization_id uuid not null,
    record_id uuid not null,
    version_id uuid not null,
    base_version_id uuid,
    logical_version bigint not null check (logical_version > 0),
    record_type text not null check (
        record_type in (
            'source','evidence','claim','entity','relation','geo_event',
            'alert_rule','alert','case','job','scenario','document',
            'publication_item','audit_event'
        )
    ),
    device_id uuid not null,
    ciphertext bytea not null,
    nonce bytea not null,
    wrapped_data_key bytea not null,
    wrap_nonce bytea not null,
    key_version integer not null check (key_version > 0),
    content_hash text not null check (content_hash ~ '^[0-9a-f]{64}$'),
    deleted boolean not null default false,
    created_at timestamptz not null default now(),
    primary key (organization_id, record_id, version_id),
    foreign key (organization_id, record_id)
        references public.record_heads(organization_id, record_id) on delete cascade,
    foreign key (organization_id, device_id)
        references public.devices(organization_id, id)
);

alter table public.record_heads
    add constraint record_heads_head_version_fk
    foreign key (organization_id, record_id, head_version_id)
    references public.record_versions(organization_id, record_id, version_id)
    deferrable initially deferred;

create table if not exists public.sync_events (
    cursor bigint generated always as identity primary key,
    event_id uuid not null unique,
    organization_id uuid not null,
    device_id uuid not null,
    record_id uuid not null,
    version_id uuid not null,
    operation text not null check (
        operation in ('upsert','delete','rewrap','resolve')
    ),
    applied boolean not null,
    received_at timestamptz not null default now(),
    foreign key (organization_id, device_id)
        references public.devices(organization_id, id),
    foreign key (organization_id, record_id, version_id)
        references public.record_versions(organization_id, record_id, version_id)
);
create index if not exists sync_events_org_cursor_idx
    on public.sync_events(organization_id, cursor);

create table if not exists public.conflicts (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null,
    record_id uuid not null,
    head_version_id uuid not null,
    incoming_version_id uuid not null,
    status text not null default 'open' check (status in ('open','resolved')),
    created_at timestamptz not null default now(),
    resolved_at timestamptz,
    resolved_by uuid references auth.users(id),
    resolution_version_id uuid,
    foreign key (organization_id, record_id)
        references public.record_heads(organization_id, record_id) on delete cascade,
    foreign key (organization_id, record_id, head_version_id)
        references public.record_versions(organization_id, record_id, version_id),
    foreign key (organization_id, record_id, incoming_version_id)
        references public.record_versions(organization_id, record_id, version_id),
    unique (organization_id, record_id, incoming_version_id)
);

create table if not exists public.encrypted_objects (
    id uuid not null,
    organization_id uuid not null references public.organizations(id) on delete cascade,
    record_id uuid not null,
    version_id uuid not null,
    device_id uuid not null,
    storage_path text not null,
    ciphertext_sha256 text not null check (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
    wrapped_data_key bytea not null,
    wrap_nonce bytea not null,
    nonce bytea not null,
    key_version integer not null check (key_version > 0),
    byte_length bigint not null check (byte_length >= 0),
    created_at timestamptz not null default now(),
    primary key (organization_id, id),
    foreign key (organization_id, record_id)
        references public.record_heads(organization_id, record_id) on delete cascade,
    foreign key (organization_id, record_id, version_id)
        references public.record_versions(organization_id, record_id, version_id),
    foreign key (organization_id, device_id)
        references public.devices(organization_id, id),
    unique (organization_id, storage_path),
    check (
        storage_path =
            organization_id::text || '/' || id::text || '/' || ciphertext_sha256
    )
);

create table if not exists public.workflow_states (
    organization_id uuid not null,
    record_id uuid not null,
    state text not null check (
        state in ('draft','editing','pending_approval','signed','recalled')
    ),
    version bigint not null default 1 check (version > 0),
    content_hash text not null check (content_hash ~ '^[0-9a-f]{64}$'),
    assigned_user_id uuid references auth.users(id),
    updated_by uuid not null references auth.users(id),
    updated_at timestamptz not null default now(),
    primary key (organization_id, record_id),
    foreign key (organization_id, record_id)
        references public.record_heads(organization_id, record_id) on delete cascade
);

create table if not exists public.audit_chain (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    record_id uuid,
    event_type text not null,
    actor_user_id uuid not null references auth.users(id),
    content_hash text not null check (content_hash ~ '^[0-9a-f]{64}$'),
    previous_hash text check (
        previous_hash is null or previous_hash ~ '^[0-9a-f]{64}$'
    ),
    event_hash text not null check (event_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default now()
);
create index if not exists audit_chain_org_created_idx
    on public.audit_chain(organization_id, created_at, id);

create table if not exists public.key_rotations (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    from_key_version integer not null check (from_key_version > 0),
    to_key_version integer not null check (to_key_version > 0),
    expected_count bigint not null check (expected_count >= 0),
    staged_count bigint not null default 0 check (staged_count >= 0),
    status text not null default 'staging' check (
        status in ('staging','committed','aborted')
    ),
    created_by uuid not null references auth.users(id),
    created_at timestamptz not null default now(),
    committed_at timestamptz,
    unique (organization_id, to_key_version)
);

create table if not exists public.key_rotation_entries (
    rotation_id uuid not null references public.key_rotations(id) on delete cascade,
    organization_id uuid not null,
    record_id uuid not null,
    version_id uuid not null,
    wrapped_data_key bytea not null,
    wrap_nonce bytea not null,
    created_at timestamptz not null default now(),
    primary key (rotation_id, organization_id, record_id, version_id),
    foreign key (organization_id, record_id, version_id)
        references public.record_versions(organization_id, record_id, version_id)
);

create table if not exists public.device_pairings (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null references public.organizations(id) on delete cascade,
    target_user_id uuid not null references auth.users(id) on delete cascade,
    code_hash text not null check (code_hash ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz not null,
    consumed_at timestamptz,
    created_by uuid not null references auth.users(id),
    created_at timestamptz not null default now(),
    unique (organization_id, code_hash)
);

create or replace function private.is_org_member(target_org uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.memberships m
        where m.organization_id = target_org
          and m.user_id = (select auth.uid())
          and m.status = 'active'
    );
$$;

create or replace function private.is_org_admin(target_org uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.memberships m
        where m.organization_id = target_org
          and m.user_id = (select auth.uid())
          and m.status = 'active'
          and m.role in ('owner','admin')
    );
$$;

create or replace function private.is_org_owner(target_org uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.memberships m
        where m.organization_id = target_org
          and m.user_id = (select auth.uid())
          and m.status = 'active'
          and m.role = 'owner'
    );
$$;

create or replace function private.can_write_record(
    target_org uuid,
    target_type text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.memberships m
        where m.organization_id = target_org
          and m.user_id = (select auth.uid())
          and m.status = 'active'
          and (
              m.role = 'owner'
              or (m.role = 'admin' and target_type in ('alert_rule','alert'))
              or (m.role = 'collector' and target_type in ('source','evidence','claim'))
              or (
                  m.role = 'analyst'
                  and target_type in (
                      'claim','entity','relation','geo_event','alert','case',
                      'job','scenario'
                  )
              )
              or (
                  m.role = 'editor'
                  and target_type in ('document','publication_item')
              )
              or (
                  m.role = 'approver'
                  and target_type in ('publication_item','audit_event')
              )
          )
    );
$$;

create or replace function private.is_active_device_owner(
    target_org uuid,
    target_device uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
        from public.devices d
        where d.organization_id = target_org
          and d.id = target_device
          and d.user_id = (select auth.uid())
          and d.status = 'active'
    );
$$;

create or replace function private.decode_base64url(value text)
returns bytea
language sql
immutable
set search_path = ''
as $$
    select decode(
        rpad(translate(value, '-_', '+/'), ((length(value) + 3) / 4) * 4, '='),
        'base64'
    );
$$;

create or replace function private.encode_base64url(value bytea)
returns text
language sql
immutable
set search_path = ''
as $$
    select rtrim(translate(encode(value, 'base64'), '+/', '-_'), '=');
$$;

create or replace function private.path_org_uuid(value text)
returns uuid
language sql
immutable
set search_path = ''
as $$
    select case
        when split_part(value, '/', 1) ~
             '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        then split_part(value, '/', 1)::uuid
        else null
    end;
$$;

revoke all on all functions in schema private from public;
grant usage on schema private to authenticated;
grant execute on function private.is_org_member(uuid) to authenticated;
grant execute on function private.is_org_admin(uuid) to authenticated;
grant execute on function private.is_org_owner(uuid) to authenticated;
grant execute on function private.can_write_record(uuid,text) to authenticated;
grant execute on function private.is_active_device_owner(uuid,uuid) to authenticated;
grant execute on function private.path_org_uuid(text) to authenticated;

create or replace function public.bootstrap_organization(
    name_ciphertext text,
    name_nonce text,
    device_id uuid,
    device_public_key text,
    device_name_ciphertext text,
    device_name_nonce text,
    key_algorithm text default 'x25519'
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    new_org uuid := gen_random_uuid();
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    if key_algorithm not in ('x25519','p256') then
        raise exception 'unsupported key algorithm';
    end if;
    insert into public.organizations(
        id,name_ciphertext,name_nonce,created_by
    ) values (
        new_org,
        private.decode_base64url(name_ciphertext),
        private.decode_base64url(name_nonce),
        actor
    );
    insert into public.memberships(organization_id,user_id,role,status)
    values (new_org,actor,'owner','active');
    insert into public.devices(
        id,organization_id,user_id,key_algorithm,public_key,
        name_ciphertext,name_nonce,status
    ) values (
        device_id,new_org,actor,key_algorithm,
        private.decode_base64url(device_public_key),
        private.decode_base64url(device_name_ciphertext),
        private.decode_base64url(device_name_nonce),
        'active'
    );
    return new_org;
end;
$$;

create or replace function public.register_device(
    organization_id uuid,
    device_id uuid,
    key_algorithm text,
    device_public_key text,
    device_name_ciphertext text,
    device_name_nonce text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not private.is_org_member(organization_id) then
        raise exception 'active membership required';
    end if;
    if key_algorithm not in ('x25519','p256') then
        raise exception 'unsupported key algorithm';
    end if;
    insert into public.devices(
        id,organization_id,user_id,key_algorithm,public_key,
        name_ciphertext,name_nonce,status
    ) values (
        device_id,organization_id,(select auth.uid()),key_algorithm,
        private.decode_base64url(device_public_key),
        private.decode_base64url(device_name_ciphertext),
        private.decode_base64url(device_name_nonce),
        'pending'
    );
    return device_id;
end;
$$;

create or replace function public.pair_device(
    organization_id uuid,
    device_id uuid,
    target_user_id uuid,
    envelope_key_version integer,
    envelope_algorithm text,
    ephemeral_public_key text,
    envelope_nonce text,
    envelope_ciphertext text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not private.is_org_admin(organization_id) then
        raise exception 'owner or admin required';
    end if;
    if not exists (
        select 1 from public.memberships m
        where m.organization_id = pair_device.organization_id
          and m.user_id = target_user_id
          and m.status = 'active'
    ) then
        raise exception 'target membership is not active';
    end if;
    update public.devices d
       set status = 'active'
     where d.organization_id = pair_device.organization_id
       and d.id = pair_device.device_id
       and d.user_id = target_user_id
       and d.status = 'pending';
    if not found then
        raise exception 'pending target device not found';
    end if;
    insert into public.key_envelopes(
        organization_id,device_id,key_version,key_algorithm,
        ephemeral_public_key,nonce,ciphertext
    ) values (
        organization_id,device_id,envelope_key_version,envelope_algorithm,
        private.decode_base64url(ephemeral_public_key),
        private.decode_base64url(envelope_nonce),
        private.decode_base64url(envelope_ciphertext)
    );
end;
$$;

create or replace function public.push_record_event(p_event jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    event_id uuid := (p_event->>'event_id')::uuid;
    org_id uuid := (p_event->>'organization_id')::uuid;
    rec_id uuid := (p_event->>'record_id')::uuid;
    ver_id uuid := (p_event->'payload'->>'version_id')::uuid;
    base_id uuid := nullif(p_event->'payload'->>'base_version_id','')::uuid;
    dev_id uuid := (p_event->'payload'->>'device_id')::uuid;
    rec_type text := p_event->'payload'->>'record_type';
    op text := p_event->>'operation';
    logical_ver bigint := (p_event->'payload'->>'version')::bigint;
    existing_cursor bigint;
    current_head public.record_heads%rowtype;
    applied boolean := false;
    new_cursor bigint;
begin
    if actor is null then raise exception 'authentication required'; end if;
    if op not in ('upsert','delete') then
        raise exception 'unsupported client operation';
    end if;
    if p_event->'payload'->>'organization_id' <> org_id::text
       or p_event->'payload'->>'record_id' <> rec_id::text then
        raise exception 'payload identity mismatch';
    end if;
    if not private.can_write_record(org_id,rec_type) then
        raise exception 'record write denied';
    end if;
    if not private.is_active_device_owner(org_id,dev_id) then
        raise exception 'active caller device required';
    end if;
    if (p_event->'payload'->>'content_hash') !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid content hash';
    end if;

    select e.cursor into existing_cursor
    from public.sync_events e where e.event_id = push_record_event.event_id;
    if existing_cursor is not null then
        return jsonb_build_object(
            'cursor',existing_cursor,'duplicate',true,'applied',false
        );
    end if;

    select * into current_head
    from public.record_heads h
    where h.organization_id = org_id and h.record_id = rec_id
    for update;

    if not found then
        if base_id is not null or logical_ver <> 1 then
            raise exception 'new record requires null base and version 1';
        end if;
        insert into public.record_heads(
            organization_id,record_id,record_type,logical_version,deleted
        ) values (org_id,rec_id,rec_type,0,false);
        current_head.organization_id := org_id;
        current_head.record_id := rec_id;
        current_head.record_type := rec_type;
        current_head.logical_version := 0;
        current_head.head_version_id := null;
    elsif current_head.record_type <> rec_type then
        raise exception 'record type is immutable';
    end if;

    insert into public.record_versions(
        organization_id,record_id,version_id,base_version_id,logical_version,
        record_type,device_id,ciphertext,nonce,wrapped_data_key,wrap_nonce,
        key_version,content_hash,deleted
    ) values (
        org_id,rec_id,ver_id,base_id,logical_ver,rec_type,dev_id,
        private.decode_base64url(p_event->'payload'->>'ciphertext'),
        private.decode_base64url(p_event->'payload'->>'nonce'),
        private.decode_base64url(p_event->'payload'->>'wrapped_data_key'),
        private.decode_base64url(p_event->'payload'->>'wrap_nonce'),
        (p_event->'payload'->>'key_version')::integer,
        lower(p_event->'payload'->>'content_hash'),
        coalesce((p_event->'payload'->>'deleted')::boolean,false)
    );

    if (
        current_head.head_version_id is null
        and base_id is null
        and logical_ver = 1
    ) or (
        current_head.head_version_id = base_id
        and logical_ver = current_head.logical_version + 1
    ) then
        applied := true;
        update public.record_heads h
           set head_version_id = ver_id,
               logical_version = logical_ver,
               deleted = coalesce(
                   (p_event->'payload'->>'deleted')::boolean,false
               ),
               updated_at = now()
         where h.organization_id = org_id and h.record_id = rec_id;
    else
        if current_head.head_version_id is null then
            raise exception 'invalid initial version';
        end if;
        insert into public.conflicts(
            organization_id,record_id,head_version_id,incoming_version_id
        ) values (
            org_id,rec_id,current_head.head_version_id,ver_id
        );
    end if;

    insert into public.sync_events(
        event_id,organization_id,device_id,record_id,version_id,
        operation,applied
    ) values (
        event_id,org_id,dev_id,rec_id,ver_id,op,applied
    ) returning cursor into new_cursor;

    return jsonb_build_object(
        'cursor',new_cursor,'duplicate',false,'applied',applied,
        'conflict',not applied,'version_id',ver_id
    );
end;
$$;

create or replace function public.pull_sync_events(
    organization_id uuid,
    after_cursor bigint default 0,
    page_size integer default 200
)
returns table (
    cursor bigint,
    event_id uuid,
    operation text,
    applied boolean,
    payload jsonb
)
language sql
stable
security invoker
set search_path = ''
as $$
    select
        e.cursor,
        e.event_id,
        e.operation,
        e.applied,
        jsonb_build_object(
            'organization_id',v.organization_id,
            'record_id',v.record_id,
            'version_id',v.version_id,
            'base_version_id',v.base_version_id,
            'record_type',v.record_type,
            'version',v.logical_version,
            'device_id',v.device_id,
            'ciphertext',private.encode_base64url(v.ciphertext),
            'nonce',private.encode_base64url(v.nonce),
            'wrapped_data_key',private.encode_base64url(v.wrapped_data_key),
            'wrap_nonce',private.encode_base64url(v.wrap_nonce),
            'key_version',v.key_version,
            'content_hash',v.content_hash,
            'deleted',v.deleted
        )
    from public.sync_events e
    join public.record_versions v
      on v.organization_id = e.organization_id
     and v.record_id = e.record_id
     and v.version_id = e.version_id
    where e.organization_id = pull_sync_events.organization_id
      and e.cursor > greatest(after_cursor,0)
    order by e.cursor
    limit least(greatest(page_size,1),500);
$$;

create or replace function public.resolve_conflict(
    conflict_id uuid,
    expected_head_version_id uuid,
    resolution_event jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    target public.conflicts%rowtype;
    pushed jsonb;
begin
    select * into target
    from public.conflicts c
    where c.id = conflict_id and c.status = 'open'
    for update;
    if not found then raise exception 'open conflict not found'; end if;
    if not private.can_write_record(
        target.organization_id,
        (select h.record_type from public.record_heads h
         where h.organization_id = target.organization_id
           and h.record_id = target.record_id)
    ) then raise exception 'record write denied'; end if;
    if (
        select h.head_version_id from public.record_heads h
        where h.organization_id = target.organization_id
          and h.record_id = target.record_id
    ) <> expected_head_version_id then
        raise exception 'head changed during resolution';
    end if;
    pushed := public.push_record_event(resolution_event);
    if not coalesce((pushed->>'applied')::boolean,false) then
        raise exception 'resolution created another conflict';
    end if;
    update public.conflicts
       set status='resolved',resolved_at=now(),resolved_by=(select auth.uid()),
           resolution_version_id=(pushed->>'version_id')::uuid
     where id=conflict_id;
    return pushed || jsonb_build_object('resolved_conflict_id',conflict_id);
end;
$$;

create or replace function public.transition_workflow(
    organization_id uuid,
    record_id uuid,
    expected_version bigint,
    target_state text,
    content_hash text
)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    actor_role text;
    current_state public.workflow_states%rowtype;
    previous_hash text;
    next_version bigint;
    calculated_hash text;
begin
    select m.role into actor_role
    from public.memberships m
    where m.organization_id = transition_workflow.organization_id
      and m.user_id = actor and m.status = 'active';
    if actor_role is null then raise exception 'active membership required'; end if;
    if content_hash !~ '^[0-9a-f]{64}$' then raise exception 'invalid content hash'; end if;

    select * into current_state
    from public.workflow_states w
    where w.organization_id = transition_workflow.organization_id
      and w.record_id = transition_workflow.record_id
    for update;

    if not found then
        if expected_version <> 0 or target_state not in ('draft','editing') then
            raise exception 'invalid initial workflow transition';
        end if;
        if actor_role not in ('owner','editor') then
            raise exception 'editor role required';
        end if;
        next_version := 1;
        insert into public.workflow_states(
            organization_id,record_id,state,version,content_hash,updated_by
        ) values (
            organization_id,record_id,target_state,next_version,
            lower(content_hash),actor
        );
    else
        if current_state.version <> expected_version then
            raise exception 'workflow version conflict';
        end if;
        if target_state = 'pending_approval'
           and actor_role not in ('owner','editor') then
            raise exception 'editor role required';
        elsif target_state in ('signed','recalled')
           and actor_role not in ('owner','approver') then
            raise exception 'approver role required';
        elsif target_state in ('draft','editing')
           and actor_role not in ('owner','editor') then
            raise exception 'editor role required';
        end if;
        if target_state = 'signed' and current_state.state <> 'pending_approval' then
            raise exception 'only pending items can be signed';
        end if;
        if target_state = 'recalled' and current_state.state <> 'signed' then
            raise exception 'only signed items can be recalled';
        end if;
        next_version := current_state.version + 1;
        update public.workflow_states
           set state=target_state,version=next_version,
               content_hash=lower(content_hash),updated_by=actor,updated_at=now()
         where workflow_states.organization_id =
                   transition_workflow.organization_id
           and workflow_states.record_id = transition_workflow.record_id;
    end if;

    select a.event_hash into previous_hash
    from public.audit_chain a
    where a.organization_id = transition_workflow.organization_id
    order by a.created_at desc,a.id desc limit 1;
    calculated_hash := encode(
        digest(
            coalesce(previous_hash,'') || organization_id::text ||
            record_id::text || target_state || next_version::text ||
            lower(content_hash) || actor::text,
            'sha256'
        ),
        'hex'
    );
    insert into public.audit_chain(
        organization_id,record_id,event_type,actor_user_id,content_hash,
        previous_hash,event_hash
    ) values (
        organization_id,record_id,'workflow:'||target_state,actor,
        lower(content_hash),previous_hash,calculated_hash
    );
    return next_version;
end;
$$;

create or replace function public.begin_key_rotation(
    organization_id uuid,
    expected_key_version integer,
    expected_count bigint
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
    rotation_id uuid := gen_random_uuid();
    current_version integer;
    actual_count bigint;
begin
    if not private.is_org_owner(organization_id) then
        raise exception 'owner required';
    end if;
    select o.key_version into current_version
    from public.organizations o
    where o.id = begin_key_rotation.organization_id
    for update;
    if current_version <> expected_key_version then
        raise exception 'expected_key_version mismatch';
    end if;
    if exists (
        select 1 from public.key_rotations r
        where r.organization_id = begin_key_rotation.organization_id
          and r.status = 'staging'
    ) then raise exception 'rotation already in progress'; end if;
    select count(*) into actual_count
    from public.record_versions v
    where v.organization_id = begin_key_rotation.organization_id;
    if actual_count <> expected_count then
        raise exception 'expected rewrap count mismatch';
    end if;
    insert into public.key_rotations(
        id,organization_id,from_key_version,to_key_version,
        expected_count,created_by
    ) values (
        rotation_id,organization_id,current_version,current_version+1,
        expected_count,(select auth.uid())
    );
    return rotation_id;
end;
$$;

create or replace function public.stage_rewrap_batch(
    rotation_id uuid,
    entries jsonb
)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
    rotation public.key_rotations%rowtype;
    entry jsonb;
    total bigint;
begin
    select * into rotation
    from public.key_rotations r
    where r.id = rotation_id and r.status = 'staging'
    for update;
    if not found then raise exception 'active rotation not found'; end if;
    if not private.is_org_owner(rotation.organization_id) then
        raise exception 'owner required';
    end if;
    if jsonb_typeof(entries) <> 'array' or jsonb_array_length(entries) > 500 then
        raise exception 'entries must be an array of at most 500';
    end if;
    for entry in select value from jsonb_array_elements(entries)
    loop
        insert into public.key_rotation_entries(
            rotation_id,organization_id,record_id,version_id,
            wrapped_data_key,wrap_nonce
        ) values (
            rotation_id,rotation.organization_id,
            (entry->>'record_id')::uuid,(entry->>'version_id')::uuid,
            private.decode_base64url(entry->>'wrapped_data_key'),
            private.decode_base64url(entry->>'wrap_nonce')
        )
        on conflict (rotation_id,organization_id,record_id,version_id)
        do update set
            wrapped_data_key=excluded.wrapped_data_key,
            wrap_nonce=excluded.wrap_nonce;
    end loop;
    select count(*) into total
    from public.key_rotation_entries e where e.rotation_id=rotation_id;
    update public.key_rotations set staged_count=total where id=rotation_id;
    return total;
end;
$$;

create or replace function public.commit_key_rotation(rotation_id uuid)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
    rotation public.key_rotations%rowtype;
    active_devices bigint;
    new_envelopes bigint;
begin
    select * into rotation
    from public.key_rotations r
    where r.id = rotation_id and r.status = 'staging'
    for update;
    if not found then raise exception 'active rotation not found'; end if;
    if not private.is_org_owner(rotation.organization_id) then
        raise exception 'owner required';
    end if;
    if rotation.staged_count <> rotation.expected_count then
        raise exception 'rewrap batch incomplete';
    end if;
    select count(*) into active_devices from public.devices d
    where d.organization_id=rotation.organization_id and d.status='active';
    select count(*) into new_envelopes from public.key_envelopes e
    where e.organization_id=rotation.organization_id
      and e.key_version=rotation.to_key_version;
    if new_envelopes <> active_devices then
        raise exception 'device envelope set incomplete';
    end if;
    if not exists (
        select 1 from public.recovery_envelopes r
        where r.organization_id=rotation.organization_id
          and r.key_version=rotation.to_key_version
    ) then raise exception 'new recovery envelope required'; end if;

    update public.record_versions v
       set wrapped_data_key=e.wrapped_data_key,
           wrap_nonce=e.wrap_nonce,
           key_version=rotation.to_key_version
      from public.key_rotation_entries e
     where e.rotation_id=rotation.id
       and v.organization_id=e.organization_id
       and v.record_id=e.record_id
       and v.version_id=e.version_id;
    update public.organizations
       set key_version=rotation.to_key_version,updated_at=now()
     where id=rotation.organization_id
       and key_version=rotation.from_key_version;
    if not found then raise exception 'organization key version changed'; end if;
    update public.key_rotations
       set status='committed',committed_at=now()
     where id=rotation.id;
    return rotation.to_key_version;
end;
$$;

create or replace function public.revoke_device(
    organization_id uuid,
    device_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    target_role text;
begin
    if not private.is_org_admin(organization_id) then
        raise exception 'owner or admin required';
    end if;
    select m.role into target_role
    from public.devices d
    join public.memberships m
      on m.organization_id=d.organization_id and m.user_id=d.user_id
    where d.organization_id=revoke_device.organization_id
      and d.id=revoke_device.device_id;
    if target_role='owner' and not private.is_org_owner(organization_id) then
        raise exception 'admin cannot revoke owner device';
    end if;
    update public.devices
       set status='revoked',revoked_at=now()
     where devices.organization_id=revoke_device.organization_id
       and devices.id=revoke_device.device_id
       and status <> 'revoked';
    return found;
end;
$$;

create or replace function public.revoke_member(
    organization_id uuid,
    target_user_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    target_role text;
    owner_count bigint;
begin
    if not private.is_org_admin(organization_id) then
        raise exception 'owner or admin required';
    end if;
    select m.role into target_role from public.memberships m
    where m.organization_id=revoke_member.organization_id
      and m.user_id=target_user_id and m.status='active'
    for update;
    if target_role is null then return false; end if;
    if target_role='owner' then
        if not private.is_org_owner(organization_id) then
            raise exception 'admin cannot revoke owner';
        end if;
        select count(*) into owner_count from public.memberships m
        where m.organization_id=revoke_member.organization_id
          and m.role='owner' and m.status='active';
        if owner_count <= 1 then
            raise exception 'cannot revoke the last owner';
        end if;
    end if;
    update public.memberships
       set status='revoked',revoked_at=now()
     where memberships.organization_id=revoke_member.organization_id
       and memberships.user_id=target_user_id;
    update public.devices
       set status='revoked',revoked_at=now()
     where devices.organization_id=revoke_member.organization_id
       and devices.user_id=target_user_id
       and devices.status <> 'revoked';
    return true;
end;
$$;

revoke all on function public.bootstrap_organization(
    text,text,uuid,text,text,text,text
) from public, anon;
revoke all on function public.register_device(
    uuid,uuid,text,text,text,text
) from public, anon;
revoke all on function public.pair_device(
    uuid,uuid,uuid,integer,text,text,text,text
) from public, anon;
revoke all on function public.push_record_event(jsonb) from public, anon;
revoke all on function public.pull_sync_events(uuid,bigint,integer) from public, anon;
revoke all on function public.resolve_conflict(uuid,uuid,jsonb) from public, anon;
revoke all on function public.transition_workflow(
    uuid,uuid,bigint,text,text
) from public, anon;
revoke all on function public.begin_key_rotation(
    uuid,integer,bigint
) from public, anon;
revoke all on function public.stage_rewrap_batch(uuid,jsonb) from public, anon;
revoke all on function public.commit_key_rotation(uuid) from public, anon;
revoke all on function public.revoke_device(uuid,uuid) from public, anon;
revoke all on function public.revoke_member(uuid,uuid) from public, anon;

grant execute on function public.bootstrap_organization(
    text,text,uuid,text,text,text,text
) to authenticated;
grant execute on function public.register_device(
    uuid,uuid,text,text,text,text
) to authenticated;
grant execute on function public.pair_device(
    uuid,uuid,uuid,integer,text,text,text,text
) to authenticated;
grant execute on function public.push_record_event(jsonb) to authenticated;
grant execute on function public.pull_sync_events(uuid,bigint,integer)
    to authenticated;
grant execute on function public.resolve_conflict(uuid,uuid,jsonb)
    to authenticated;
grant execute on function public.transition_workflow(
    uuid,uuid,bigint,text,text
) to authenticated;
grant execute on function public.begin_key_rotation(
    uuid,integer,bigint
) to authenticated;
grant execute on function public.stage_rewrap_batch(uuid,jsonb) to authenticated;
grant execute on function public.commit_key_rotation(uuid) to authenticated;
grant execute on function public.revoke_device(uuid,uuid) to authenticated;
grant execute on function public.revoke_member(uuid,uuid) to authenticated;

revoke all on all tables in schema public from anon;
grant select,insert,update,delete on
    public.organizations,
    public.memberships,
    public.devices,
    public.key_envelopes,
    public.recovery_envelopes,
    public.record_heads,
    public.record_versions,
    public.sync_events,
    public.conflicts,
    public.encrypted_objects,
    public.workflow_states,
    public.audit_chain,
    public.key_rotations,
    public.key_rotation_entries,
    public.device_pairings
to authenticated;
grant usage,select on all sequences in schema public to authenticated;

alter table public.organizations enable row level security;
alter table public.memberships enable row level security;
alter table public.devices enable row level security;
alter table public.key_envelopes enable row level security;
alter table public.recovery_envelopes enable row level security;
alter table public.record_heads enable row level security;
alter table public.record_versions enable row level security;
alter table public.sync_events enable row level security;
alter table public.conflicts enable row level security;
alter table public.encrypted_objects enable row level security;
alter table public.workflow_states enable row level security;
alter table public.audit_chain enable row level security;
alter table public.key_rotations enable row level security;
alter table public.key_rotation_entries enable row level security;
alter table public.device_pairings enable row level security;

create policy organizations_select on public.organizations
for select to authenticated using (private.is_org_member(id));
create policy organizations_update on public.organizations
for update to authenticated using (private.is_org_owner(id))
with check (private.is_org_owner(id));

create policy memberships_select on public.memberships
for select to authenticated using (private.is_org_member(organization_id));

create policy devices_select on public.devices
for select to authenticated using (private.is_org_member(organization_id));

create policy key_envelopes_select on public.key_envelopes
for select to authenticated using (
    private.is_org_owner(organization_id)
    or exists (
        select 1 from public.devices d
        where d.organization_id=key_envelopes.organization_id
          and d.id=key_envelopes.device_id
          and d.user_id=(select auth.uid())
          and d.status='active'
    )
);
create policy key_envelopes_write on public.key_envelopes
for all to authenticated using (private.is_org_owner(organization_id))
with check (private.is_org_owner(organization_id));

create policy recovery_envelopes_owner_only on public.recovery_envelopes
for all to authenticated using (private.is_org_owner(organization_id))
with check (private.is_org_owner(organization_id));

create policy record_heads_select on public.record_heads
for select to authenticated using (private.is_org_member(organization_id));

create policy record_versions_select on public.record_versions
for select to authenticated using (private.is_org_member(organization_id));

create policy sync_events_select on public.sync_events
for select to authenticated using (private.is_org_member(organization_id));

create policy conflicts_select on public.conflicts
for select to authenticated using (private.is_org_member(organization_id));

create policy encrypted_objects_select on public.encrypted_objects
for select to authenticated using (private.is_org_member(organization_id));
create policy encrypted_objects_insert on public.encrypted_objects
for insert to authenticated with check (
    private.is_active_device_owner(organization_id,device_id)
    and private.can_write_record(
        organization_id,
        (select h.record_type from public.record_heads h
         where h.organization_id=encrypted_objects.organization_id
           and h.record_id=encrypted_objects.record_id)
    )
);
create policy encrypted_objects_delete on public.encrypted_objects
for delete to authenticated using (private.is_org_admin(organization_id));

create policy workflow_states_select on public.workflow_states
for select to authenticated using (private.is_org_member(organization_id));

create policy audit_chain_select on public.audit_chain
for select to authenticated using (private.is_org_member(organization_id));

create policy key_rotations_select on public.key_rotations
for select to authenticated using (private.is_org_owner(organization_id));

create policy key_rotation_entries_select on public.key_rotation_entries
for select to authenticated using (private.is_org_owner(organization_id));

create policy device_pairings_select on public.device_pairings
for select to authenticated using (
    target_user_id=(select auth.uid())
    or private.is_org_admin(organization_id)
);

insert into storage.buckets (id,name,public,file_size_limit)
values ('defense-v9-encrypted','defense-v9-encrypted',false,104857600)
on conflict (id) do update set public=false,file_size_limit=excluded.file_size_limit;

create policy v9_storage_select on storage.objects
for select to authenticated using (
    bucket_id='defense-v9-encrypted'
    and private.is_org_member(private.path_org_uuid(name))
);
create policy v9_storage_insert on storage.objects
for insert to authenticated with check (
    bucket_id='defense-v9-encrypted'
    and private.is_org_member(private.path_org_uuid(name))
    and exists (
        select 1 from public.encrypted_objects o
        where o.organization_id=private.path_org_uuid(name)
          and o.storage_path=name
    )
);
create policy v9_storage_delete on storage.objects
for delete to authenticated using (
    bucket_id='defense-v9-encrypted'
    and private.is_org_admin(private.path_org_uuid(name))
);

commit;
