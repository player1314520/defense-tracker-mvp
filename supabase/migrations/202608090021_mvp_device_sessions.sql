-- Bind every privileged request to the Supabase Auth session and an active
-- approved device.  Revoking the device therefore invalidates old JWTs even
-- when the Auth access token itself has not expired yet.
-- MVP EMPTY-DATABASE PRECHECK (must return exactly 0 before migration):
-- select count(*) as existing_devices from public.devices;
begin;

alter table public.devices
    add column if not exists device_kind text;

do $device_backfill$
begin
    if exists (
        select 1 from public.devices d where d.device_kind is null
    ) then
        raise exception 'device_kind backfill required before MVP migration';
    end if;
end;
$device_backfill$;

alter table public.devices
    alter column device_kind set default 'desktop',
    alter column device_kind set not null;

alter table public.organizations
    add column if not exists mvp_singleton boolean not null default true;

do $single_organization$
begin
    if (select count(*) from public.organizations) > 1 then
        raise exception 'MVP requires a single organization';
    end if;
end;
$single_organization$;

do $constraints$
begin
    if not exists (
        select 1 from pg_catalog.pg_constraint
        where conname = 'devices_device_kind_check'
          and conrelid = 'public.devices'::regclass
    ) then
        alter table public.devices
            add constraint devices_device_kind_check
            check (device_kind in ('desktop','browser'));
    end if;
    if not exists (
        select 1 from pg_catalog.pg_constraint
        where conname = 'organizations_mvp_singleton_check'
          and conrelid = 'public.organizations'::regclass
    ) then
        alter table public.organizations
            add constraint organizations_mvp_singleton_check
            check (mvp_singleton);
    end if;
    if not exists (
        select 1 from pg_catalog.pg_constraint
        where conname = 'organizations_mvp_singleton_key'
          and conrelid = 'public.organizations'::regclass
    ) then
        alter table public.organizations
            add constraint organizations_mvp_singleton_key
            unique (mvp_singleton);
    end if;
end;
$constraints$;

create table if not exists private.device_sessions (
    session_id text primary key check (
        length(session_id) between 16 and 256
        and session_id ~ '^[A-Za-z0-9._~-]+$'
    ),
    organization_id uuid not null,
    device_id uuid not null,
    user_id uuid not null references auth.users(id) on delete cascade,
    status text not null default 'active'
        check (status in ('active','revoked')),
    bound_at timestamptz not null default statement_timestamp(),
    last_seen_at timestamptz not null default statement_timestamp(),
    revoked_at timestamptz,
    foreign key (organization_id,device_id)
        references public.devices(organization_id,id) on delete cascade,
    check (
        (status = 'active' and revoked_at is null)
        or (status = 'revoked' and revoked_at is not null)
    )
);

create index if not exists device_sessions_device_idx
    on private.device_sessions(organization_id,device_id,status);
create index if not exists device_sessions_user_idx
    on private.device_sessions(user_id,status);

create table if not exists private.mvp_owner_bootstrap (
    singleton boolean primary key default true check (singleton),
    email_sha256 text not null unique check (
        email_sha256 ~ '^[0-9a-f]{64}$'
    ),
    status text not null,
    auth_user_id uuid,
    payload_sha256 text,
    organization_id uuid,
    device_id uuid,
    created_at timestamptz not null default statement_timestamp(),
    updated_at timestamptz not null default statement_timestamp(),
    finalized_at timestamptz
);

alter table private.mvp_owner_bootstrap
    add column if not exists payload_sha256 text,
    add column if not exists organization_id uuid,
    add column if not exists device_id uuid;
alter table private.mvp_owner_bootstrap
    drop constraint if exists mvp_owner_bootstrap_status_check;
alter table private.mvp_owner_bootstrap
    add constraint mvp_owner_bootstrap_status_check check (
        status in (
            'preparing','invited','failed','provisioned','finalized'
        )
    );

do $bootstrap_constraints$
begin
    if not exists (
        select 1 from pg_catalog.pg_constraint
        where conname = 'mvp_owner_bootstrap_payload_check'
          and conrelid = 'private.mvp_owner_bootstrap'::regclass
    ) then
        alter table private.mvp_owner_bootstrap
            add constraint mvp_owner_bootstrap_payload_check check (
                payload_sha256 is null
                or payload_sha256 ~ '^[0-9a-f]{64}$'
            );
    end if;
    if not exists (
        select 1 from pg_catalog.pg_constraint
        where conname = 'mvp_owner_bootstrap_state_check'
          and conrelid = 'private.mvp_owner_bootstrap'::regclass
    ) then
        alter table private.mvp_owner_bootstrap
            add constraint mvp_owner_bootstrap_state_check check (
                status in ('preparing','failed')
                or (
                    status = 'invited'
                    and auth_user_id is not null
                )
                or (
                    status in ('provisioned','finalized')
                    and auth_user_id is not null
                    and payload_sha256 is not null
                    and organization_id is not null
                    and device_id is not null
                )
            );
    end if;
end;
$bootstrap_constraints$;

revoke all on table private.device_sessions
    from public, anon, authenticated, service_role;
revoke all on table private.mvp_owner_bootstrap
    from public, anon, authenticated, service_role;

create or replace function private.current_session_id()
returns text
language sql
stable
security definer
set search_path = ''
as $$
    select case
        when nullif((select auth.jwt()) ->> 'session_id','')
             ~ '^[A-Za-z0-9._~-]{16,256}$'
        then (select auth.jwt()) ->> 'session_id'
        else null
    end;
$$;

create or replace function private.has_active_device_session(
    target_org uuid,
    target_device uuid default null
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select exists (
        select 1
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
          and ds.organization_id = target_org
          and ds.user_id = (select auth.uid())
          and ds.status = 'active'
          and ds.revoked_at is null
          and d.status = 'active'
          and (target_device is null or ds.device_id = target_device)
    );
$$;

create or replace function private.require_active_device_session(
    target_org uuid,
    target_device uuid default null
)
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
    if not private.has_active_device_session(target_org,target_device) then
        raise exception 'active device session required'
            using errcode = '42501';
    end if;
end;
$$;

create or replace function private.can_register_device_session(
    target_org uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select
        (select auth.uid()) is not null
        and private.current_session_id() is not null
        and not exists (
            select 1
            from private.device_sessions ds
            where ds.session_id = private.current_session_id()
              and ds.status = 'revoked'
        )
        and exists (
            select 1
            from public.memberships m
            where m.organization_id = target_org
              and m.user_id = (select auth.uid())
              and (
                  m.status = 'active'
                  or (
                      m.status = 'invited'
                      and m.invite_expires_at > statement_timestamp()
                  )
              )
        );
$$;

create or replace function private.can_accept_member_invitation_session()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select
        (select auth.uid()) is not null
        and private.current_session_id() is not null
        and not exists (
            select 1
            from private.device_sessions ds
            where ds.session_id = private.current_session_id()
              and ds.status = 'revoked'
        );
$$;

create or replace function public.bind_device_session(
    p_organization_id uuid,
    p_device_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    caller_session text := private.current_session_id();
    existing private.device_sessions%rowtype;
begin
    if actor is null or caller_session is null then
        raise exception 'authenticated session required'
            using errcode = '42501';
    end if;

    perform o.id
    from public.organizations o
    where o.id = p_organization_id
    for update;
    if not found then
        raise exception 'organization not found';
    end if;

    perform m.user_id
    from public.memberships m
    where m.organization_id = p_organization_id
      and m.user_id = actor
      and m.status = 'active';
    if not found then
        raise exception 'active membership required'
            using errcode = '42501';
    end if;

    perform d.id
    from public.devices d
    where d.organization_id = p_organization_id
      and d.id = p_device_id
      and d.user_id = actor
      and d.status = 'active'
    for update;
    if not found then
        raise exception 'active owned device required'
            using errcode = '42501';
    end if;

    select ds.* into existing
    from private.device_sessions ds
    where ds.session_id = caller_session
    for update;
    if found then
        if existing.status = 'revoked' then
            raise exception 'device session is revoked'
                using errcode = '42501';
        end if;
        if existing.organization_id is distinct from p_organization_id
           or existing.device_id is distinct from p_device_id
           or existing.user_id is distinct from actor then
            raise exception 'session is already bound to another device'
                using errcode = '42501';
        end if;
        update private.device_sessions
           set last_seen_at = statement_timestamp()
         where session_id = caller_session;
    else
        insert into private.device_sessions(
            session_id,organization_id,device_id,user_id
        ) values (
            caller_session,p_organization_id,p_device_id,actor
        );
    end if;

    return jsonb_build_object(
        'organization_id',p_organization_id,
        'device_id',p_device_id,
        'status','active'
    );
end;
$$;

create or replace function public.bootstrap_mvp_first_owner(
    p_owner_user_id uuid,
    p_session_id text,
    p_organization_id uuid,
    p_name_ciphertext text,
    p_name_nonce text,
    p_device_id uuid,
    p_device_public_key text,
    p_device_name_ciphertext text,
    p_device_name_nonce text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    request_role text := pg_catalog.coalesce(
        pg_catalog.nullif(
            pg_catalog.current_setting('request.jwt.claim.role',true),''
        ),
        (select auth.jwt()) ->> 'role',
        ''
    );
    marker private.mvp_owner_bootstrap%rowtype;
    decoded_name_ciphertext bytea;
    decoded_name_nonce bytea;
    decoded_device_public_key bytea;
    decoded_device_name_ciphertext bytea;
    decoded_device_name_nonce bytea;
    payload_hash text;
    auth_user_count bigint;
    organization_count bigint;
    membership_count bigint;
    device_count bigint;
    session_count bigint;
begin
    if request_role <> 'service_role'
       or pg_catalog.coalesce((select auth.jwt()) ->> 'role','')
          <> 'service_role' then
        raise exception 'service role required'
            using errcode = '42501';
    end if;
    if p_owner_user_id is null
       or p_organization_id is null
       or p_device_id is null
       or p_session_id is null
       or length(p_session_id) not between 16 and 256
       or p_session_id !~ '^[A-Za-z0-9._~-]+$'
       or p_name_ciphertext is null
       or length(p_name_ciphertext) not between 22 and 1368
       or length(p_name_ciphertext) % 4 = 1
       or p_name_ciphertext !~ '^[A-Za-z0-9_-]+$'
       or p_name_nonce is null
       or length(p_name_nonce) <> 16
       or p_name_nonce !~ '^[A-Za-z0-9_-]+$'
       or p_device_public_key is null
       or length(p_device_public_key) <> 87
       or p_device_public_key !~ '^[A-Za-z0-9_-]+$'
       or p_device_name_ciphertext is null
       or length(p_device_name_ciphertext) not between 22 and 1368
       or length(p_device_name_ciphertext) % 4 = 1
       or p_device_name_ciphertext !~ '^[A-Za-z0-9_-]+$'
       or p_device_name_nonce is null
       or length(p_device_name_nonce) <> 16
       or p_device_name_nonce !~ '^[A-Za-z0-9_-]+$' then
        raise exception 'invalid bootstrap payload';
    end if;

    begin
        decoded_name_ciphertext := private.decode_base64url(
            p_name_ciphertext
        );
        decoded_name_nonce := private.decode_base64url(p_name_nonce);
        decoded_device_public_key := private.decode_base64url(
            p_device_public_key
        );
        decoded_device_name_ciphertext := private.decode_base64url(
            p_device_name_ciphertext
        );
        decoded_device_name_nonce := private.decode_base64url(
            p_device_name_nonce
        );
    exception when others then
        raise exception 'invalid bootstrap payload';
    end;
    if octet_length(decoded_name_ciphertext) not between 16 and 1024
       or octet_length(decoded_name_nonce) <> 12
       or octet_length(decoded_device_public_key) <> 65
       or pg_catalog.get_byte(decoded_device_public_key,0) <> 4
       or octet_length(decoded_device_name_ciphertext)
          not between 16 and 1024
       or octet_length(decoded_device_name_nonce) <> 12
       or private.encode_base64url(decoded_name_ciphertext)
          <> p_name_ciphertext
       or private.encode_base64url(decoded_name_nonce) <> p_name_nonce
       or private.encode_base64url(decoded_device_public_key)
          <> p_device_public_key
       or private.encode_base64url(decoded_device_name_ciphertext)
          <> p_device_name_ciphertext
       or private.encode_base64url(decoded_device_name_nonce)
          <> p_device_name_nonce then
        raise exception 'invalid bootstrap payload';
    end if;

    payload_hash := pg_catalog.encode(
        extensions.digest(
            pg_catalog.convert_to(
                jsonb_build_object(
                    'owner_user_id',p_owner_user_id,
                    'session_id',p_session_id,
                    'organization_id',p_organization_id,
                    'name_ciphertext',p_name_ciphertext,
                    'name_nonce',p_name_nonce,
                    'device_id',p_device_id,
                    'device_public_key',p_device_public_key,
                    'device_name_ciphertext',p_device_name_ciphertext,
                    'device_name_nonce',p_device_name_nonce,
                    'key_algorithm','p256',
                    'device_kind','desktop'
                )::text,
                'UTF8'
            ),
            'sha256'
        ),
        'hex'
    );

    perform pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'defense-tracker:mvp:first-owner',0
        )
    );
    select b.* into marker
    from private.mvp_owner_bootstrap b
    where b.singleton
    for update;
    if not found then
        raise exception 'bootstrap marker unavailable'
            using errcode = '42501';
    end if;
    if marker.auth_user_id is distinct from p_owner_user_id then
        raise exception 'bootstrap identity mismatch'
            using errcode = '42501';
    end if;

    if marker.status in ('provisioned','finalized') then
        if marker.payload_sha256 is distinct from payload_hash
           or marker.organization_id is distinct from p_organization_id
           or marker.device_id is distinct from p_device_id then
            raise exception 'bootstrap payload mismatch'
                using errcode = '42501';
        end if;
        select count(*) into auth_user_count from auth.users;
        select count(*) into organization_count from public.organizations;
        select count(*) into membership_count from public.memberships;
        select count(*) into device_count from public.devices;
        select count(*) into session_count from private.device_sessions;
        if auth_user_count <> 1
           or organization_count <> 1
           or membership_count <> 1
           or device_count <> 1
           or session_count <> 1
           or not exists (
               select 1 from public.organizations o
               where o.id = p_organization_id
                 and o.created_by = p_owner_user_id
                 and o.name_ciphertext = decoded_name_ciphertext
                 and o.name_nonce = decoded_name_nonce
                 and o.mvp_singleton
           )
           or not exists (
               select 1 from public.memberships m
               where m.organization_id = p_organization_id
                 and m.user_id = p_owner_user_id
                 and m.role = 'owner'
                 and m.status = 'active'
           )
           or not exists (
               select 1 from public.devices d
               where d.organization_id = p_organization_id
                 and d.id = p_device_id
                 and d.user_id = p_owner_user_id
                 and d.key_algorithm = 'p256'
                 and d.device_kind = 'desktop'
                 and d.status = 'active'
                 and d.public_key = decoded_device_public_key
                 and d.name_ciphertext = decoded_device_name_ciphertext
                 and d.name_nonce = decoded_device_name_nonce
           )
           or not exists (
               select 1 from private.device_sessions ds
               where ds.session_id = p_session_id
                 and ds.organization_id = p_organization_id
                 and ds.device_id = p_device_id
                 and ds.user_id = p_owner_user_id
                 and ds.status = 'active'
                 and ds.revoked_at is null
           ) then
            raise exception 'bootstrap state mismatch'
                using errcode = '42501';
        end if;
        return jsonb_build_object(
            'status','provisioned',
            'organization_id',p_organization_id,
            'device_id',p_device_id
        );
    end if;

    if marker.status <> 'invited' then
        raise exception 'bootstrap marker is not ready'
            using errcode = '42501';
    end if;
    select count(*) into auth_user_count from auth.users;
    if auth_user_count <> 1
       or not exists (
           select 1
           from auth.users u
           where u.id = p_owner_user_id
             and marker.email_sha256 = pg_catalog.encode(
                 extensions.digest(
                     pg_catalog.convert_to(
                         pg_catalog.lower(pg_catalog.btrim(u.email)),
                         'UTF8'
                     ),
                     'sha256'
                 ),
                 'hex'
             )
       ) then
        raise exception 'bootstrap identity mismatch'
            using errcode = '42501';
    end if;
    perform s.id
    from auth.sessions s
    where s.id::text = p_session_id
      and s.user_id = p_owner_user_id
    for share;
    if not found then
        raise exception 'active owner session required'
            using errcode = '42501';
    end if;

    select count(*) into organization_count from public.organizations;
    select count(*) into membership_count from public.memberships;
    select count(*) into device_count from public.devices;
    select count(*) into session_count from private.device_sessions;
    if organization_count <> 0
       or membership_count <> 0
       or device_count <> 0
       or session_count <> 0 then
        raise exception 'bootstrap requires empty MVP tenant state'
            using errcode = '42501';
    end if;

    insert into public.organizations(
        id,name_ciphertext,name_nonce,created_by,mvp_singleton
    ) values (
        p_organization_id,decoded_name_ciphertext,decoded_name_nonce,
        p_owner_user_id,true
    );
    insert into public.memberships(
        organization_id,user_id,role,status
    ) values (
        p_organization_id,p_owner_user_id,'owner','active'
    );
    insert into public.devices(
        id,organization_id,user_id,key_algorithm,public_key,
        name_ciphertext,name_nonce,status,device_kind
    ) values (
        p_device_id,p_organization_id,p_owner_user_id,'p256',
        decoded_device_public_key,decoded_device_name_ciphertext,
        decoded_device_name_nonce,'active','desktop'
    );
    insert into private.device_sessions(
        session_id,organization_id,device_id,user_id,status
    ) values (
        p_session_id,p_organization_id,p_device_id,p_owner_user_id,
        'active'
    );
    update private.mvp_owner_bootstrap
       set status = 'provisioned',
           payload_sha256 = payload_hash,
           organization_id = p_organization_id,
           device_id = p_device_id,
           updated_at = statement_timestamp()
     where singleton
       and status = 'invited';
    if not found then
        raise exception 'bootstrap marker changed'
            using errcode = '40001';
    end if;

    return jsonb_build_object(
        'status','provisioned',
        'organization_id',p_organization_id,
        'device_id',p_device_id
    );
end;
$$;

create or replace function private.revoke_bound_device_sessions()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if new.status = 'revoked' and old.status is distinct from new.status then
        update private.device_sessions
           set status = 'revoked',
               revoked_at = coalesce(revoked_at,statement_timestamp()),
               last_seen_at = statement_timestamp()
         where organization_id = new.organization_id
           and device_id = new.id
           and status = 'active';
    end if;
    return new;
end;
$$;

drop trigger if exists revoke_bound_device_sessions
    on public.devices;
create trigger revoke_bound_device_sessions
after update of status on public.devices
for each row execute function private.revoke_bound_device_sessions();

create or replace function private.revoke_member_device_sessions()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if tg_op = 'DELETE' then
        update private.device_sessions
           set status = 'revoked',
               revoked_at = coalesce(revoked_at,statement_timestamp()),
               last_seen_at = statement_timestamp()
         where organization_id = old.organization_id
           and user_id = old.user_id
           and status = 'active';
        return old;
    end if;
    if old.status = 'active'
       and new.status is distinct from 'active' then
        update private.device_sessions
           set status = 'revoked',
               revoked_at = coalesce(revoked_at,statement_timestamp()),
               last_seen_at = statement_timestamp()
         where organization_id = old.organization_id
           and user_id = old.user_id
           and status = 'active';
    end if;
    return new;
end;
$$;

drop trigger if exists revoke_member_device_sessions
    on public.memberships;
create trigger revoke_member_device_sessions
after update of status or delete on public.memberships
for each row execute function private.revoke_member_device_sessions();

create or replace function private.is_org_member(target_org uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select private.has_active_device_session(target_org,null)
       and exists (
            select 1 from public.memberships m
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
    select private.has_active_device_session(target_org,null)
       and exists (
            select 1 from public.memberships m
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
    select private.has_active_device_session(target_org,null)
       and exists (
            select 1 from public.memberships m
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
    select private.has_active_device_session(target_org,null)
       and exists (
            select 1
            from public.memberships m
            where m.organization_id = target_org
              and m.user_id = (select auth.uid())
              and m.status = 'active'
              and (
                  m.role = 'owner'
                  or (
                      m.role = 'admin'
                      and target_type in ('alert_rule','alert')
                  )
                  or (
                      m.role = 'collector'
                      and target_type in ('source','evidence','claim')
                  )
                  or (
                      m.role = 'analyst'
                      and target_type in (
                          'claim','entity','relation','geo_event','alert',
                          'case','job','scenario'
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
    select private.has_active_device_session(target_org,target_device)
       and exists (
            select 1 from public.devices d
            where d.organization_id = target_org
              and d.id = target_device
              and d.user_id = (select auth.uid())
              and d.status = 'active'
       );
$$;

create or replace function private.can_read_device(
    target_org uuid,
    target_user uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select (
        private.has_active_device_session(target_org,null)
        and exists (
            select 1 from public.memberships actor_membership
            where actor_membership.organization_id = target_org
              and actor_membership.user_id = (select auth.uid())
              and actor_membership.status = 'active'
              and actor_membership.role in ('owner','admin')
        )
    ) or (
        target_user = (select auth.uid())
        and (
            (
                private.has_active_device_session(target_org,null)
                and exists (
                    select 1 from public.memberships m
                    where m.organization_id = target_org
                      and m.user_id = target_user
                      and m.status = 'active'
                )
            )
            or exists (
                select 1 from public.memberships m
                where m.organization_id = target_org
                  and m.user_id = target_user
                  and m.status = 'invited'
                  and m.invite_expires_at > statement_timestamp()
            )
        )
    );
$$;

-- The private implementations are callable only through the guarded public
-- wrappers below.  PostgREST does not expose the private schema, but the
-- explicit revoke keeps the database boundary fail-closed as well.
revoke all on function private.begin_member_invitation(uuid,text,text)
    from public, anon, authenticated;
revoke all on function private.accept_member_invitation()
    from public, anon, authenticated;
revoke all on function private.cancel_member_invitation(uuid)
    from public, anon, authenticated;
revoke all on function private.list_member_invitations(uuid)
    from public, anon, authenticated;
revoke all on function private.register_device(uuid,uuid,text,text,text,text)
    from public, anon, authenticated;
revoke all on function private.pair_device(
    uuid,uuid,uuid,integer,text,text,text,text
) from public, anon, authenticated;
revoke all on function private.revoke_device(uuid,uuid)
    from public, anon, authenticated;
revoke all on function private.revoke_member(uuid,uuid)
    from public, anon, authenticated;

create or replace function public.begin_member_invitation(
    p_organization_id uuid,
    p_email_sha256 text,
    p_role text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
begin
    perform private.require_active_device_session(p_organization_id,null);
    if not private.is_org_admin(p_organization_id) then
        raise exception 'owner or admin required'
            using errcode = '42501';
    end if;
    if p_role = 'owner'
       and not private.is_org_owner(p_organization_id) then
        raise exception 'only owner can invite owner'
            using errcode = '42501';
    end if;
    return private.begin_member_invitation(
        p_organization_id,p_email_sha256,p_role
    );
end;
$$;

create or replace function public.accept_member_invitation()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
    if not private.can_accept_member_invitation_session() then
        raise exception 'invitation session denied'
            using errcode = '42501';
    end if;
    return private.accept_member_invitation();
end;
$$;

create or replace function public.cancel_member_invitation(
    p_invitation_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    target_org uuid;
begin
    select r.organization_id into target_org
    from private.member_invitation_requests r
    where r.id = p_invitation_id;
    if target_org is null then
        return false;
    end if;
    perform private.require_active_device_session(target_org,null);
    if not private.is_org_admin(target_org) then
        raise exception 'owner or admin required'
            using errcode = '42501';
    end if;
    return private.cancel_member_invitation(p_invitation_id);
end;
$$;

create or replace function public.list_member_invitations(
    p_organization_id uuid
)
returns table (
    invitation_id uuid,
    invitation_role text,
    invitation_status text,
    expires_at timestamptz,
    created_at timestamptz,
    finalized_at timestamptz,
    cancelled_at timestamptz
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
    perform private.require_active_device_session(p_organization_id,null);
    if not private.is_org_admin(p_organization_id) then
        raise exception 'owner or admin required'
            using errcode = '42501';
    end if;
    return query
    select * from private.list_member_invitations(p_organization_id);
end;
$$;

drop function if exists public.register_device(uuid,uuid,text,text,text,text);
create or replace function public.register_device(
    organization_id uuid,
    device_id uuid,
    key_algorithm text,
    device_public_key text,
    device_name_ciphertext text,
    device_name_nonce text,
    device_kind text default 'desktop'
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
    registered uuid;
begin
    if device_kind is null
       or device_kind not in ('desktop','browser') then
        raise exception 'invalid device kind';
    end if;
    if not private.can_register_device_session(organization_id) then
        raise exception 'device registration session denied'
            using errcode = '42501';
    end if;
    registered := private.register_device(
        organization_id,device_id,key_algorithm,device_public_key,
        device_name_ciphertext,device_name_nonce
    );
    update public.devices d
       set device_kind = register_device.device_kind
     where d.organization_id = register_device.organization_id
       and d.id = registered
       and d.user_id = (select auth.uid());
    return registered;
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
    perform private.require_active_device_session(organization_id,null);
    if not private.is_org_admin(organization_id) then
        raise exception 'owner or admin required'
            using errcode = '42501';
    end if;
    perform private.pair_device(
        organization_id,device_id,target_user_id,envelope_key_version,
        envelope_algorithm,ephemeral_public_key,envelope_nonce,
        envelope_ciphertext
    );
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
begin
    perform private.require_active_device_session(organization_id,null);
    if not private.is_org_admin(organization_id) then
        raise exception 'owner or admin required'
            using errcode = '42501';
    end if;
    return private.revoke_device(organization_id,device_id);
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
begin
    perform private.require_active_device_session(organization_id,null);
    if not private.is_org_admin(organization_id) then
        raise exception 'owner or admin required'
            using errcode = '42501';
    end if;
    return private.revoke_member(organization_id,target_user_id);
end;
$$;

do $rename_pull$
begin
    if to_regprocedure(
        'public.mvp_unbound_pull_sync_events(uuid,bigint,integer)'
    ) is null then
        alter function public.pull_sync_events(uuid,bigint,integer)
            rename to mvp_unbound_pull_sync_events;
    end if;
end;
$rename_pull$;
revoke all on function public.mvp_unbound_pull_sync_events(
    uuid,bigint,integer
) from public, anon, authenticated;
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
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
    perform private.require_active_device_session(organization_id,null);
    return query
    select * from public.mvp_unbound_pull_sync_events(
        organization_id,after_cursor,page_size
    );
end;
$$;

do $rename_workflow$
begin
    if to_regprocedure(
        'public.mvp_unbound_transition_workflow(uuid,uuid,bigint,text,text)'
    ) is null then
        alter function public.transition_workflow(
            uuid,uuid,bigint,text,text
        ) rename to mvp_unbound_transition_workflow;
    end if;
end;
$rename_workflow$;
revoke all on function public.mvp_unbound_transition_workflow(
    uuid,uuid,bigint,text,text
) from public, anon, authenticated;
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
begin
    perform private.require_active_device_session(organization_id,null);
    return public.mvp_unbound_transition_workflow(
        organization_id,record_id,expected_version,target_state,content_hash
    );
end;
$$;

-- Signed-object operations had direct role checks in their original bodies.
-- Wrap them as well so a revoked session cannot continue deleting objects.
do $rename_object_delete$
begin
    if to_regprocedure(
        'public.mvp_unbound_begin_encrypted_object_delete(uuid,uuid)'
    ) is null then
        alter function public.begin_encrypted_object_delete(uuid,uuid)
            rename to mvp_unbound_begin_encrypted_object_delete;
    end if;
    if to_regprocedure(
        'public.mvp_unbound_cancel_encrypted_object_delete(uuid)'
    ) is null then
        alter function public.cancel_encrypted_object_delete(uuid)
            rename to mvp_unbound_cancel_encrypted_object_delete;
    end if;
    if to_regprocedure(
        'public.mvp_unbound_finalize_encrypted_object_delete(uuid)'
    ) is null then
        alter function public.finalize_encrypted_object_delete(uuid)
            rename to mvp_unbound_finalize_encrypted_object_delete;
    end if;
    if to_regprocedure(
        'public.mvp_unbound_list_pending_encrypted_object_deletes(uuid)'
    ) is null then
        alter function public.list_pending_encrypted_object_deletes(uuid)
            rename to mvp_unbound_list_pending_encrypted_object_deletes;
    end if;
end;
$rename_object_delete$;

revoke all on function public.mvp_unbound_begin_encrypted_object_delete(
    uuid,uuid
) from public, anon, authenticated;
revoke all on function public.mvp_unbound_cancel_encrypted_object_delete(uuid)
    from public, anon, authenticated;
revoke all on function public.mvp_unbound_finalize_encrypted_object_delete(uuid)
    from public, anon, authenticated;
revoke all on function public.mvp_unbound_list_pending_encrypted_object_deletes(
    uuid
) from public, anon, authenticated;

create or replace function public.begin_encrypted_object_delete(
    organization_id uuid,
    object_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
    perform private.require_active_device_session(organization_id,null);
    return public.mvp_unbound_begin_encrypted_object_delete(
        organization_id,object_id
    );
end;
$$;

create or replace function public.cancel_encrypted_object_delete(request_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    target_org uuid;
begin
    select r.organization_id into target_org
    from private.encrypted_object_delete_requests r
    where r.id = request_id;
    if target_org is null then
        raise exception 'delete request not found';
    end if;
    perform private.require_active_device_session(target_org,null);
    return public.mvp_unbound_cancel_encrypted_object_delete(request_id);
end;
$$;

create or replace function public.finalize_encrypted_object_delete(request_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    target_org uuid;
begin
    select r.organization_id into target_org
    from private.encrypted_object_delete_requests r
    where r.id = request_id;
    if target_org is null then
        raise exception 'delete request not found';
    end if;
    perform private.require_active_device_session(target_org,null);
    return public.mvp_unbound_finalize_encrypted_object_delete(request_id);
end;
$$;

create or replace function public.list_pending_encrypted_object_deletes(
    organization_id uuid
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
    perform private.require_active_device_session(organization_id,null);
    return public.mvp_unbound_list_pending_encrypted_object_deletes(
        organization_id
    );
end;
$$;

-- Restrictive policies AND the session/device predicate with every existing
-- permissive tenant policy. Onboarding retains only the caller's four-column
-- membership control plane and that caller's pending device rows.
drop policy if exists mvp_session_organizations on public.organizations;
create policy mvp_session_organizations
on public.organizations as restrictive
for all to authenticated
using (private.has_active_device_session(organizations.id,null))
with check (private.has_active_device_session(organizations.id,null));

drop policy if exists mvp_session_memberships on public.memberships;
drop policy if exists mvp_session_memberships_select on public.memberships;
create policy mvp_session_memberships_select
on public.memberships as restrictive
for select to authenticated
using (
    private.has_active_device_session(memberships.organization_id,null)
    or (
        memberships.user_id = (select auth.uid())
        and (
            memberships.status = 'active'
            or (
                memberships.status = 'invited'
                and memberships.invite_expires_at > statement_timestamp()
            )
        )
    )
);

revoke select on table public.memberships from authenticated;
grant select (organization_id,user_id,role,status)
    on table public.memberships to authenticated;

-- Replace the older permissive device policy so an active member with a lost
-- local identity can observe only the pending row it just registered. Active
-- devices remain invisible until bind_device_session succeeds with a local ID.
drop policy if exists devices_select on public.devices;
create policy devices_select on public.devices
for select to authenticated using (
    (
        private.has_active_device_session(devices.organization_id,null)
        and private.can_read_device(
            devices.organization_id,devices.user_id
        )
    )
    or (
        devices.user_id = (select auth.uid())
        and devices.status = 'pending'
        and private.can_register_device_session(devices.organization_id)
    )
);

drop policy if exists mvp_session_devices on public.devices;
create policy mvp_session_devices
on public.devices as restrictive
for all to authenticated
using (
    private.has_active_device_session(devices.organization_id,null)
    or (
        devices.user_id = (select auth.uid())
        and devices.status = 'pending'
        and private.can_register_device_session(devices.organization_id)
    )
)
with check (
    private.has_active_device_session(devices.organization_id,null)
    or (
        devices.user_id = (select auth.uid())
        and devices.status = 'pending'
        and private.can_register_device_session(devices.organization_id)
    )
);

do $policies$
declare
    target_table text;
begin
    foreach target_table in array array[
        'key_envelopes','recovery_envelopes','record_heads',
        'record_versions','sync_events','sync_wakeups','conflicts',
        'encrypted_objects','workflow_states','audit_chain','key_rotations',
        'key_rotation_entries','device_pairings'
    ] loop
        execute format(
            'drop policy if exists mvp_session_backstop on public.%I',
            target_table
        );
        execute format(
            'create policy mvp_session_backstop on public.%I '
            || 'as restrictive for all to authenticated '
            || 'using (private.has_active_device_session('
            || 'organization_id,null)) '
            || 'with check (private.has_active_device_session('
            || 'organization_id,null))',
            target_table
        );
    end loop;
end;
$policies$;

drop policy if exists mvp_session_storage_backstop on storage.objects;
create policy mvp_session_storage_backstop
on storage.objects as restrictive
for all to authenticated
using (
    bucket_id <> 'defense-v9-encrypted'
    or private.has_active_device_session(
        private.path_org_uuid(name),null
    )
)
with check (
    bucket_id <> 'defense-v9-encrypted'
    or private.has_active_device_session(
        private.path_org_uuid(name),null
    )
);

revoke all on function public.bind_device_session(uuid,uuid)
    from public, anon, authenticated;
grant execute on function public.bind_device_session(uuid,uuid)
    to authenticated;

revoke all on function public.bootstrap_mvp_first_owner(
    uuid,text,uuid,text,text,uuid,text,text,text
) from public, anon, authenticated, service_role;
grant execute on function public.bootstrap_mvp_first_owner(
    uuid,text,uuid,text,text,uuid,text,text,text
) to service_role;

revoke all on function public.register_device(
    uuid,uuid,text,text,text,text,text
) from public, anon, authenticated;
grant execute on function public.register_device(
    uuid,uuid,text,text,text,text,text
) to authenticated;

revoke all on function public.begin_member_invitation(uuid,text,text)
    from public, anon, authenticated;
revoke all on function public.accept_member_invitation()
    from public, anon, authenticated;
revoke all on function public.cancel_member_invitation(uuid)
    from public, anon, authenticated;
revoke all on function public.list_member_invitations(uuid)
    from public, anon, authenticated;
revoke all on function public.pair_device(
    uuid,uuid,uuid,integer,text,text,text,text
) from public, anon, authenticated;
revoke all on function public.revoke_device(uuid,uuid)
    from public, anon, authenticated;
revoke all on function public.revoke_member(uuid,uuid)
    from public, anon, authenticated;
revoke all on function public.pull_sync_events(uuid,bigint,integer)
    from public, anon, authenticated;
revoke all on function public.transition_workflow(
    uuid,uuid,bigint,text,text
) from public, anon, authenticated;
revoke all on function public.begin_encrypted_object_delete(uuid,uuid)
    from public, anon, authenticated;
revoke all on function public.cancel_encrypted_object_delete(uuid)
    from public, anon, authenticated;
revoke all on function public.finalize_encrypted_object_delete(uuid)
    from public, anon, authenticated;
revoke all on function public.list_pending_encrypted_object_deletes(uuid)
    from public, anon, authenticated;

grant execute on function public.begin_member_invitation(uuid,text,text)
    to authenticated;
grant execute on function public.accept_member_invitation()
    to authenticated;
grant execute on function public.cancel_member_invitation(uuid)
    to authenticated;
grant execute on function public.list_member_invitations(uuid)
    to authenticated;
grant execute on function public.pair_device(
    uuid,uuid,uuid,integer,text,text,text,text
) to authenticated;
grant execute on function public.revoke_device(uuid,uuid)
    to authenticated;
grant execute on function public.revoke_member(uuid,uuid)
    to authenticated;
grant execute on function public.pull_sync_events(uuid,bigint,integer)
    to authenticated;
grant execute on function public.transition_workflow(
    uuid,uuid,bigint,text,text
) to authenticated;
grant execute on function public.begin_encrypted_object_delete(uuid,uuid)
    to authenticated;
grant execute on function public.cancel_encrypted_object_delete(uuid)
    to authenticated;
grant execute on function public.finalize_encrypted_object_delete(uuid)
    to authenticated;
grant execute on function public.list_pending_encrypted_object_deletes(uuid)
    to authenticated;

-- MVP is one pre-provisioned organization.  Account JWTs cannot create a
-- second tenant; operators bootstrap the first organization out of band.
revoke all on function public.bootstrap_organization(
    text,text,uuid,text,text,text,text
) from public, anon, authenticated, service_role;
revoke all on function public.bootstrap_organization(
    text,text,uuid,text,text,text,text,uuid
) from public, anon, authenticated, service_role;
revoke all on function private.bootstrap_organization(
    text,text,uuid,text,text,text,text
) from public, anon, authenticated, service_role;
revoke all on function private.bootstrap_organization(
    text,text,uuid,text,text,text,text,uuid
) from public, anon, authenticated, service_role;

revoke all on function private.current_session_id()
    from public, anon, authenticated, service_role;
revoke all on function private.has_active_device_session(uuid,uuid)
    from public, anon, authenticated, service_role;
revoke all on function private.require_active_device_session(uuid,uuid)
    from public, anon, authenticated, service_role;
revoke all on function private.can_register_device_session(uuid)
    from public, anon, authenticated, service_role;
revoke all on function private.can_accept_member_invitation_session()
    from public, anon, authenticated, service_role;
revoke all on function private.revoke_bound_device_sessions()
    from public, anon, authenticated, service_role;
revoke all on function private.revoke_member_device_sessions()
    from public, anon, authenticated, service_role;

-- RLS expressions execute as the caller and therefore need EXECUTE on the
-- two boolean predicates they reference. Neither function exposes rows or
-- accepts a session identifier; the verified JWT remains the only source.
grant usage on schema private to authenticated;
grant execute on function private.has_active_device_session(uuid,uuid)
    to authenticated;
grant execute on function private.can_register_device_session(uuid)
    to authenticated;

comment on table private.device_sessions is
    'Server-side binding of an Auth session_id to one approved device.';
comment on function public.bind_device_session(uuid,uuid) is
    'Bind the caller JWT session_id to an active device owned by that caller.';
comment on function public.bootstrap_mvp_first_owner(
    uuid,text,uuid,text,text,uuid,text,text,text
) is 'Service-only, single-use first Owner and desktop session bootstrap.';

commit;
