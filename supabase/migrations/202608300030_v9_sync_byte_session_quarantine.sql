-- Bound encrypted sync bytes, isolate poisoned plaintext, and revoke the
-- caller's bound device session without accepting caller-controlled IDs.
begin;

-- Organization deletion may cascade to the capacity ledger before it cascades
-- to memberships.  A missing ledger is corruption while the parent remains,
-- but it is expected once the parent organization has been deleted.
create or replace function private.release_organization_seat(
    p_organization_id uuid,
    p_reservation_key text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    removed_count integer := 0;
begin
    perform u.organization_id
    from private.organization_seat_usage u
    where u.organization_id = p_organization_id
    for update;
    if not found then
        if not exists (
            select 1
            from public.organizations o
            where o.id = p_organization_id
        ) then
            return;
        end if;
        raise exception 'organization capacity state is unavailable';
    end if;
    delete from private.organization_seat_reservations r
    where r.organization_id = p_organization_id
      and r.reservation_key = p_reservation_key;
    get diagnostics removed_count = row_count;
    if removed_count = 1 then
        update private.organization_seat_usage u
        set used_seats = greatest(0,u.used_seats - 1),
            updated_at = statement_timestamp()
        where u.organization_id = p_organization_id;
    end if;
end;
$$;

revoke all on function private.release_organization_seat(uuid,text)
    from public, anon, authenticated, service_role;

alter table public.record_versions
    add constraint record_versions_ciphertext_v9_0_size_check
    check (octet_length(ciphertext) between 17 and 1048592)
    not valid;

alter table private.sync_event_daily_usage
    add column if not exists ciphertext_bytes bigint not null default 0;

do $usage_constraints$
begin
    if not exists (
        select 1
        from pg_catalog.pg_constraint
        where conname = 'sync_event_daily_usage_ciphertext_bytes_check'
          and conrelid = 'private.sync_event_daily_usage'::regclass
    ) then
        alter table private.sync_event_daily_usage
            add constraint sync_event_daily_usage_ciphertext_bytes_check
            check (ciphertext_bytes between 0 and 67108864);
    end if;
end;
$usage_constraints$;

create table private.organization_sync_daily_usage (
    organization_id uuid not null
        references public.organizations(id) on delete cascade,
    usage_date date not null,
    event_count integer not null check (event_count between 1 and 100000),
    ciphertext_bytes bigint not null
        check (ciphertext_bytes between 1 and 536870912),
    updated_at timestamptz not null default statement_timestamp(),
    primary key (organization_id,usage_date)
);

revoke all on table private.organization_sync_daily_usage
    from public, anon, authenticated, service_role;

create or replace function private.enforce_sync_event_daily_quota()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    device_owner uuid;
    decoded_ciphertext_bytes bigint;
    resulting_count integer;
    resulting_bytes bigint;
    utc_day date := (statement_timestamp() at time zone 'UTC')::date;
begin
    -- push_record_event returns existing event IDs before INSERT.  Keep the
    -- trigger idempotent for direct INSERT ... ON CONFLICT fixtures too.
    if exists (
        select 1 from public.sync_events e where e.event_id = new.event_id
    ) then
        return new;
    end if;
    if actor is null then
        raise exception 'authenticated event owner required';
    end if;
    select d.user_id into device_owner
    from public.devices d
    where d.organization_id = new.organization_id
      and d.id = new.device_id;
    if device_owner is distinct from actor then
        raise exception 'event device owner mismatch';
    end if;
    select
        octet_length(v.ciphertext)
        + octet_length(v.nonce)
        + octet_length(v.wrapped_data_key)
        + octet_length(v.wrap_nonce)
      into decoded_ciphertext_bytes
    from public.record_versions v
    where v.organization_id = new.organization_id
      and v.record_id = new.record_id
      and v.version_id = new.version_id;
    if decoded_ciphertext_bytes is null then
        raise exception 'event encrypted version not found';
    end if;

    insert into private.sync_event_daily_usage(
        user_id,usage_date,event_count,ciphertext_bytes
    ) values (actor,utc_day,1,decoded_ciphertext_bytes)
    on conflict (user_id,usage_date) do update
       set event_count = private.sync_event_daily_usage.event_count + 1,
           ciphertext_bytes =
               private.sync_event_daily_usage.ciphertext_bytes
               + excluded.ciphertext_bytes,
           updated_at = statement_timestamp()
       where private.sync_event_daily_usage.event_count < 1000
         and private.sync_event_daily_usage.ciphertext_bytes
             <= 67108864 - excluded.ciphertext_bytes
    returning event_count,ciphertext_bytes
      into resulting_count,resulting_bytes;
    if resulting_count is null then
        if exists (
            select 1
            from private.sync_event_daily_usage u
            where u.user_id = actor
              and u.usage_date = utc_day
              and u.event_count >= 1000
        ) then
            raise exception 'daily sync event limit exceeded';
        end if;
        raise exception 'daily user sync byte limit exceeded';
    end if;

    insert into private.organization_sync_daily_usage(
        organization_id,usage_date,event_count,ciphertext_bytes
    ) values (new.organization_id,utc_day,1,decoded_ciphertext_bytes)
    on conflict (organization_id,usage_date) do update
       set event_count =
               private.organization_sync_daily_usage.event_count + 1,
           ciphertext_bytes =
               private.organization_sync_daily_usage.ciphertext_bytes
               + excluded.ciphertext_bytes,
           updated_at = statement_timestamp()
       where private.organization_sync_daily_usage.ciphertext_bytes
             <= 536870912 - excluded.ciphertext_bytes
    returning ciphertext_bytes into resulting_bytes;
    if resulting_bytes is null then
        -- Raising here rolls back the user reservation and the record/event
        -- insert in the same database transaction.
        raise exception 'daily organization sync byte limit exceeded';
    end if;
    return new;
end;
$$;

drop trigger if exists sync_events_daily_quota_guard
    on public.sync_events;
create trigger sync_events_daily_quota_guard
before insert on public.sync_events
for each row execute function private.enforce_sync_event_daily_quota();

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
declare
    sync_row record;
    encoded_payload jsonb;
    encoded_row_bytes bigint;
    -- JSON array brackets are two bytes; each row after the first adds a comma.
    cumulative_encoded_bytes bigint := 2;
    emitted_rows integer := 0;
    bounded_page_size integer :=
        least(greatest(coalesce(page_size,200),1),500);
    -- Keeps pre-v9.0 ciphertext (formerly capped at 16 MiB plus tag)
    -- pullable after base64url expansion while new inserts remain at 1 MiB.
    max_encoded_page_bytes constant bigint := 25165824;
begin
    perform private.require_active_device_session(organization_id,null);
    for sync_row in
        select
            e.cursor,
            e.event_id,
            e.operation,
            e.applied,
            v.organization_id,
            v.record_id,
            v.version_id,
            v.base_version_id,
            v.record_type,
            v.logical_version,
            v.device_id,
            v.ciphertext,
            v.nonce,
            v.wrapped_data_key,
            v.wrap_nonce,
            v.key_version,
            v.content_hash,
            v.deleted
        from public.sync_events e
        join public.record_versions v
          on v.organization_id = e.organization_id
         and v.record_id = e.record_id
         and v.version_id = e.version_id
        where e.organization_id = pull_sync_events.organization_id
          and e.cursor > greatest(coalesce(after_cursor,0),0)
        order by e.cursor
        limit bounded_page_size
    loop
        encoded_payload := jsonb_build_object(
            'organization_id',sync_row.organization_id,
            'record_id',sync_row.record_id,
            'version_id',sync_row.version_id,
            'base_version_id',sync_row.base_version_id,
            'record_type',sync_row.record_type,
            'version',sync_row.logical_version,
            'device_id',sync_row.device_id,
            'ciphertext',private.encode_base64url(sync_row.ciphertext),
            'nonce',private.encode_base64url(sync_row.nonce),
            'wrapped_data_key',
                private.encode_base64url(sync_row.wrapped_data_key),
            'wrap_nonce',private.encode_base64url(sync_row.wrap_nonce),
            'key_version',sync_row.key_version,
            'content_hash',sync_row.content_hash,
            'deleted',sync_row.deleted
        );
        encoded_row_bytes := octet_length(convert_to(
            jsonb_build_object(
                'cursor',sync_row.cursor,
                'event_id',sync_row.event_id,
                'operation',sync_row.operation,
                'applied',sync_row.applied,
                'payload',encoded_payload
            )::text,
            'UTF8'
        )) + case when emitted_rows > 0 then 1 else 0 end;
        if cumulative_encoded_bytes + encoded_row_bytes
           > max_encoded_page_bytes then
            if emitted_rows = 0 then
                raise exception
                    'sync event exceeds pull byte limit; administrator repair required';
            end if;
            exit;
        end if;
        cursor := sync_row.cursor;
        event_id := sync_row.event_id;
        operation := sync_row.operation;
        applied := sync_row.applied;
        payload := encoded_payload;
        cumulative_encoded_bytes :=
            cumulative_encoded_bytes + encoded_row_bytes;
        emitted_rows := emitted_rows + 1;
        return next;
    end loop;
end;
$$;

create table private.device_session_revocation_audit (
    id bigint generated always as identity primary key,
    session_sha256 text not null check (session_sha256 ~ '^[0-9a-f]{64}$'),
    organization_id uuid not null,
    device_id uuid not null,
    user_id uuid not null references auth.users(id) on delete cascade,
    revoked_at timestamptz not null default statement_timestamp(),
    unique (session_sha256,user_id)
);

revoke all on table private.device_session_revocation_audit
    from public, anon, authenticated, service_role;

create or replace function public.revoke_current_device_session()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    current_session text := private.current_session_id();
    bound_session private.device_sessions%rowtype;
    was_active boolean;
begin
    if actor is null or current_session is null then
        raise exception 'authenticated jwt session required'
            using errcode = '42501';
    end if;
    select ds.* into bound_session
    from private.device_sessions ds
    where ds.session_id = current_session
      and ds.user_id = actor
    for update;
    if not found then
        raise exception 'current device session is not bound'
            using errcode = '42501';
    end if;
    was_active := bound_session.status = 'active';
    if was_active then
        update private.device_sessions ds
           set status = 'revoked',
               revoked_at = statement_timestamp(),
               last_seen_at = statement_timestamp()
         where ds.session_id = current_session
           and ds.user_id = actor;
    end if;
    insert into private.device_session_revocation_audit(
        session_sha256,organization_id,device_id,user_id
    ) values (
        encode(
            extensions.digest(convert_to(current_session,'UTF8'),'sha256'),
            'hex'
        ),
        bound_session.organization_id,
        bound_session.device_id,
        actor
    ) on conflict (session_sha256,user_id) do nothing;
    return jsonb_build_object(
        'revoked',true,
        'already_revoked',not was_active,
        'organization_id',bound_session.organization_id,
        'device_id',bound_session.device_id
    );
end;
$$;

comment on function public.revoke_current_device_session() is
    'Revokes only auth.uid() current JWT session_id. Production Auth access-token lifetime should remain at or below 900 seconds.';

create table private.sync_event_quarantine_reports (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null
        references public.organizations(id) on delete cascade,
    event_cursor bigint not null check (event_cursor > 0),
    event_id uuid not null references public.sync_events(event_id),
    record_id uuid not null,
    version_id uuid not null,
    logical_version bigint not null check (logical_version > 0),
    record_type text not null check (length(record_type) between 1 and 64),
    reporter_user_id uuid not null
        references auth.users(id) on delete cascade,
    reporter_device_id uuid not null,
    failure_code text not null check (failure_code in (
        'invalid_json','invalid_schema','unsupported_schema',
        'integrity_failure','decrypt_failure'
    )),
    status text not null default 'open' check (
        status in ('open','tombstoned','repaired')
    ),
    report_count integer not null default 1 check (report_count > 0),
    first_reported_at timestamptz not null default statement_timestamp(),
    last_reported_at timestamptz not null default statement_timestamp(),
    resolved_at timestamptz,
    resolved_by uuid references auth.users(id),
    resolution_version_id uuid,
    resolution_cursor bigint,
    unique (organization_id,event_id,reporter_user_id,failure_code),
    foreign key (organization_id,record_id,version_id)
        references public.record_versions(
            organization_id,record_id,version_id
        ) on delete cascade,
    foreign key (organization_id,reporter_device_id)
        references public.devices(organization_id,id)
);

create index sync_event_quarantine_open_idx
    on private.sync_event_quarantine_reports(
        organization_id,status,last_reported_at desc
    );

revoke all on table private.sync_event_quarantine_reports
    from public, anon, authenticated, service_role;

create or replace function public.report_sync_event_quarantine(
    p_organization_id uuid,
    p_event_cursor bigint,
    p_event_id uuid,
    p_record_id uuid,
    p_version_id uuid,
    p_failure_code text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    reporter_device uuid;
    source_record_type text;
    source_logical_version bigint;
    report_id uuid;
    report_status text;
begin
    perform private.require_active_device_session(p_organization_id,null);
    if p_failure_code not in (
        'invalid_json','invalid_schema','unsupported_schema',
        'integrity_failure','decrypt_failure'
    ) then
        raise exception 'unsupported quarantine failure code';
    end if;
    select ds.device_id into reporter_device
    from private.device_sessions ds
    where ds.session_id = private.current_session_id()
      and ds.user_id = actor
      and ds.organization_id = p_organization_id
      and ds.status = 'active';
    if reporter_device is null then
        raise exception 'active reporting device session required'
            using errcode = '42501';
    end if;
    select v.record_type,v.logical_version
      into source_record_type,source_logical_version
    from public.sync_events e
    join public.record_versions v
      on v.organization_id = e.organization_id
     and v.record_id = e.record_id
     and v.version_id = e.version_id
    where e.organization_id = p_organization_id
      and e.cursor = p_event_cursor
      and e.event_id = p_event_id
      and e.record_id = p_record_id
      and e.version_id = p_version_id
      and e.applied = true;
    if source_record_type is null then
        raise exception 'quarantine event identity mismatch';
    end if;
    insert into private.sync_event_quarantine_reports(
        organization_id,event_cursor,event_id,record_id,version_id,
        logical_version,record_type,reporter_user_id,reporter_device_id,
        failure_code
    ) values (
        p_organization_id,p_event_cursor,p_event_id,p_record_id,p_version_id,
        source_logical_version,source_record_type,actor,reporter_device,
        p_failure_code
    )
    on conflict (
        organization_id,event_id,reporter_user_id,failure_code
    ) do update
       set report_count =
               private.sync_event_quarantine_reports.report_count + 1,
           last_reported_at = statement_timestamp()
    returning id,status into report_id,report_status;
    return jsonb_build_object(
        'report_id',report_id,
        'status',report_status
    );
end;
$$;

create or replace function public.list_sync_quarantine_reports(
    p_organization_id uuid,
    p_limit integer default 50
)
returns table (
    report_id uuid,
    event_cursor bigint,
    record_id uuid,
    version_id uuid,
    logical_version bigint,
    record_type text,
    failure_code text,
    status text,
    report_count integer,
    first_reported_at timestamptz,
    last_reported_at timestamptz,
    resolved_at timestamptz
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
    perform private.require_active_device_session(p_organization_id,null);
    if not private.is_org_admin(p_organization_id) then
        raise exception 'organization admin required'
            using errcode = '42501';
    end if;
    return query
    select
        q.id,q.event_cursor,q.record_id,q.version_id,q.logical_version,
        q.record_type,q.failure_code,q.status,q.report_count,
        q.first_reported_at,q.last_reported_at,q.resolved_at
    from private.sync_event_quarantine_reports q
    where q.organization_id = p_organization_id
    order by
        case when q.status = 'open' then 0 else 1 end,
        q.last_reported_at desc,
        q.id
    limit least(greatest(coalesce(p_limit,50),1),100);
end;
$$;

create or replace function public.admin_tombstone_quarantined_record(
    p_report_id uuid,
    p_event jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    report_row private.sync_event_quarantine_reports%rowtype;
    head_row public.record_heads%rowtype;
    payload jsonb;
    tombstone_event uuid;
    tombstone_version uuid;
    tombstone_device uuid;
    submitted_key_version integer;
    current_key_version integer;
    tombstone_cursor bigint;
    canonical_request jsonb;
    incoming_request_hash text;
begin
    select q.* into report_row
    from private.sync_event_quarantine_reports q
    where q.id = p_report_id
    for update;
    if not found or report_row.status <> 'open' then
        raise exception 'open quarantine report required';
    end if;
    perform private.require_active_device_session(
        report_row.organization_id,null
    );
    if not private.is_org_admin(report_row.organization_id) then
        raise exception 'organization admin required'
            using errcode = '42501';
    end if;
    perform private.validate_sync_ciphertext_event(p_event);
    payload := p_event->'payload';
    tombstone_event := (p_event->>'event_id')::uuid;
    tombstone_version := (payload->>'version_id')::uuid;
    tombstone_device := (payload->>'device_id')::uuid;
    submitted_key_version := (payload->>'key_version')::integer;
    if p_event->>'organization_id' <> report_row.organization_id::text
       or p_event->>'record_id' <> report_row.record_id::text
       or p_event->>'operation' <> 'delete'
       or payload->>'organization_id' <> report_row.organization_id::text
       or payload->>'record_id' <> report_row.record_id::text
       or payload->>'record_type' <> report_row.record_type
       or nullif(payload->>'base_version_id','')::uuid
          <> report_row.version_id
       or (payload->>'version')::bigint
          <> report_row.logical_version + 1
       or coalesce((payload->>'deleted')::boolean,false) is not true then
        raise exception 'quarantine tombstone event does not match report';
    end if;
    if not private.is_active_device_owner(
        report_row.organization_id,tombstone_device
    ) then
        raise exception 'active caller device required'
            using errcode = '42501';
    end if;
    -- Match push_record_event lock ordering before organization/head locks.
    perform pg_advisory_xact_lock(
        hashtextextended(tombstone_event::text,0)
    );
    if exists (
        select 1
        from public.sync_events e
        where e.event_id = tombstone_event
    ) then
        raise exception 'quarantine tombstone event id already exists';
    end if;
    select o.key_version into current_key_version
    from public.organizations o
    where o.id = report_row.organization_id
    for share;
    if submitted_key_version <> current_key_version then
        raise exception 'record key version is not current';
    end if;
    if exists (
        select 1
        from public.key_rotations r
        where r.organization_id = report_row.organization_id
          and r.status = 'staging'
    ) then
        raise exception 'key rotation in progress';
    end if;
    select h.* into head_row
    from public.record_heads h
    where h.organization_id = report_row.organization_id
      and h.record_id = report_row.record_id
    for update;
    if not found
       or head_row.head_version_id <> report_row.version_id
       or head_row.logical_version <> report_row.logical_version then
        raise exception
            'quarantined version is no longer head; mark repaired instead';
    end if;
    insert into public.record_versions(
        organization_id,record_id,version_id,base_version_id,
        logical_version,record_type,device_id,ciphertext,nonce,
        wrapped_data_key,wrap_nonce,key_version,content_hash,deleted
    ) values (
        report_row.organization_id,report_row.record_id,tombstone_version,
        report_row.version_id,report_row.logical_version + 1,
        report_row.record_type,tombstone_device,
        private.decode_base64url(payload->>'ciphertext'),
        private.decode_base64url(payload->>'nonce'),
        private.decode_base64url(payload->>'wrapped_data_key'),
        private.decode_base64url(payload->>'wrap_nonce'),
        submitted_key_version,lower(payload->>'content_hash'),true
    );
    update public.record_heads h
       set head_version_id = tombstone_version,
           logical_version = report_row.logical_version + 1,
           deleted = true,
           updated_at = statement_timestamp()
     where h.organization_id = report_row.organization_id
       and h.record_id = report_row.record_id;
    canonical_request := jsonb_build_object(
        'event_id',tombstone_event,
        'organization_id',report_row.organization_id,
        'record_id',report_row.record_id,
        'operation','delete',
        'payload',jsonb_build_object(
            'organization_id',report_row.organization_id,
            'record_id',report_row.record_id,
            'version_id',tombstone_version,
            'base_version_id',report_row.version_id,
            'device_id',tombstone_device,
            'record_type',report_row.record_type,
            'version',report_row.logical_version + 1,
            'key_version',submitted_key_version,
            'ciphertext',payload->>'ciphertext',
            'nonce',payload->>'nonce',
            'wrapped_data_key',payload->>'wrapped_data_key',
            'wrap_nonce',payload->>'wrap_nonce',
            'content_hash',lower(payload->>'content_hash'),
            'deleted',true
        )
    );
    incoming_request_hash := encode(
        extensions.digest(
            convert_to(canonical_request::text,'UTF8'),
            'sha256'
        ),
        'hex'
    );
    insert into public.sync_events(
        event_id,organization_id,device_id,record_id,version_id,
        operation,applied,request_hash
    ) values (
        tombstone_event,report_row.organization_id,tombstone_device,
        report_row.record_id,tombstone_version,'delete',true,
        incoming_request_hash
    ) returning cursor into tombstone_cursor;
    update private.sync_event_quarantine_reports q
       set status = 'tombstoned',
           resolved_at = statement_timestamp(),
           resolved_by = actor,
           resolution_version_id = tombstone_version,
           resolution_cursor = tombstone_cursor
     where q.organization_id = report_row.organization_id
       and q.record_id = report_row.record_id
       and q.version_id = report_row.version_id
       and q.status = 'open';
    return jsonb_build_object(
        'tombstoned',true,
        'version_id',tombstone_version,
        'cursor',tombstone_cursor
    );
end;
$$;

create or replace function public.admin_mark_quarantine_repaired(
    p_report_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    report_row private.sync_event_quarantine_reports%rowtype;
    current_head uuid;
    current_deleted boolean;
    repair_cursor bigint;
begin
    select q.* into report_row
    from private.sync_event_quarantine_reports q
    where q.id = p_report_id
    for update;
    if not found or report_row.status <> 'open' then
        raise exception 'open quarantine report required';
    end if;
    perform private.require_active_device_session(
        report_row.organization_id,null
    );
    if not private.is_org_admin(report_row.organization_id) then
        raise exception 'organization admin required'
            using errcode = '42501';
    end if;
    select h.head_version_id,h.deleted
      into current_head,current_deleted
    from public.record_heads h
    where h.organization_id = report_row.organization_id
      and h.record_id = report_row.record_id
    for share;
    if current_head is null
       or current_head = report_row.version_id
       or current_deleted then
        raise exception 'a newer non-deleted repair version is required';
    end if;
    select max(e.cursor) into repair_cursor
    from public.sync_events e
    where e.organization_id = report_row.organization_id
      and e.record_id = report_row.record_id
      and e.version_id = current_head
      and e.applied = true;
    if repair_cursor is null then
        raise exception 'repair sync event not found';
    end if;
    update private.sync_event_quarantine_reports q
       set status = 'repaired',
           resolved_at = statement_timestamp(),
           resolved_by = actor,
           resolution_version_id = current_head,
           resolution_cursor = repair_cursor
     where q.organization_id = report_row.organization_id
       and q.record_id = report_row.record_id
       and q.version_id = report_row.version_id
       and q.status = 'open';
    return jsonb_build_object(
        'repaired',true,
        'version_id',current_head,
        'cursor',repair_cursor
    );
end;
$$;



-- Extend the existing service-role purge without removing or renaming any
-- previously returned aggregate fields.
create or replace function private.purge_access_application_data(
    p_now timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    expired_invitations integer := 0;
    expired_memberships integer := 0;
    stale_approvals integer := 0;
    pending_deleted integer := 0;
    contacts_purged integer := 0;
    invitation_contacts_purged integer := 0;
    audit_deleted integer := 0;
    applications_deleted integer := 0;
    rate_buckets_deleted integer := 0;
    invitation_audit_deleted integer := 0;
    event_usage_deleted integer := 0;
    organization_sync_daily_usage_deleted integer := 0;
    device_session_revocation_audit_deleted integer := 0;
    sync_event_quarantine_reports_deleted integer := 0;
    provisioning_grace interval := interval '5 minutes';
    contact_retention_limit interval := interval '24 hours';
begin
    if p_now is null then
        raise exception 'purge timestamp is required';
    end if;

    -- Expired invitation records are terminal before their digest is removed.
    update private.member_invitation_requests r
       set status = 'cancelled',
           cancelled_at = coalesce(r.cancelled_at,p_now),
           -- Keep an in-flight fenced attempt identifiable so its completion
           -- path can compensate a just-created Auth user after this close.
           provisioning_state = case
               when r.provisioning_state = 'leased'
                and r.provisioning_lease_until > p_now
               then r.provisioning_state
               else 'terminal_failed'
           end,
           provisioning_attempt_id = case
               when r.provisioning_state = 'leased'
                and r.provisioning_lease_until > p_now
               then r.provisioning_attempt_id
               else null
           end,
           provisioning_lease_until = case
               when r.provisioning_state = 'leased'
                and r.provisioning_lease_until > p_now
               then r.provisioning_lease_until
               else null
           end
     where r.status = 'requested'
       and r.expires_at <= p_now;
    get diagnostics expired_invitations = row_count;

    update public.memberships m
       set status = 'revoked',
           revoked_at = coalesce(m.revoked_at,p_now)
     where m.status = 'invited'
       and m.invite_expires_at <= p_now;
    get diagnostics expired_memberships = row_count;

    -- Approval is a bounded hand-off, not an indefinite contact store.  Give
    -- the synchronous Edge -> Auth hand-off a small claim grace and respect a
    -- live, attempt-fenced provisioning lease.  Neither can cross the hard
    -- contact-retention deadline: at 24 hours the application is closed even
    -- if an invalid/stuck lease claims a later expiry.
    with stale as (
        update private.access_applications a
           set status = 'cancelled',
               decision_reason_code = coalesce(
                   a.decision_reason_code,'retention_window_elapsed'
               ),
               updated_at = p_now
         where a.status = 'approved'
           and a.reviewed_at <= p_now
           and (
               a.reviewed_at + contact_retention_limit <= p_now
               or (
                   a.reviewed_at + provisioning_grace <= p_now
                   and not exists (
                       select 1
                       from private.member_invitation_requests r
                       where r.id = a.invitation_request_id
                         and r.status = 'requested'
                         and r.provisioning_state = 'leased'
                         and r.provisioning_attempt_id is not null
                         and r.provisioning_lease_until > p_now
                   )
               )
           )
        returning
            a.id,a.organization_id,a.reviewed_by_audit_id,
            a.invitation_request_id
    ), closed_requests as (
        update private.member_invitation_requests r
           set status = 'cancelled',
               cancelled_at = coalesce(r.cancelled_at,p_now),
               -- Only the hard 24-hour branch can select an application with
               -- a live lease.  Preserve that attempt fence for compensation;
               -- every non-live request is terminal and cannot be reclaimed.
               provisioning_state = case
                   when r.provisioning_state = 'leased'
                    and r.provisioning_lease_until > p_now
                   then r.provisioning_state
                   else 'terminal_failed'
               end,
               provisioning_attempt_id = case
                   when r.provisioning_state = 'leased'
                    and r.provisioning_lease_until > p_now
                   then r.provisioning_attempt_id
                   else null
               end,
               provisioning_lease_until = case
                   when r.provisioning_state = 'leased'
                    and r.provisioning_lease_until > p_now
                   then r.provisioning_lease_until
                   else null
               end
          from stale s
         where r.id = s.invitation_request_id
           and r.status = 'requested'
        returning r.id
    ), logged as (
        insert into private.access_application_audit(
            application_id,organization_id,actor_audit_id,event_type,
            previous_status,next_status,reason_code,occurred_at
        )
        select
            s.id,s.organization_id,s.reviewed_by_audit_id,
            'invitation_cancelled','approved','cancelled',
            'retention_window_elapsed',p_now
        from stale s
        returning 1
    )
    select count(*)::integer into stale_approvals
    from logged
    cross join lateral (
        select count(*) from closed_requests
    ) closed_request_count;

    delete from private.access_applications a
    where a.status = 'pending'
      and a.created_at <= p_now - interval '29 days';
    get diagnostics pending_deleted = row_count;

    update private.access_applications a
       set email_hmac = null,
           email_ciphertext = null,
           email_nonce = null,
           email_key_version = null,
           last_ip_hmac = null,
           last_user_agent_hmac = null,
           invitation_request_id = null,
           contact_purged_at = p_now,
           updated_at = p_now
     where a.status <> 'pending'
       -- A still-approved row is inside the bounded grace or has a live lease.
       -- The hard 24-hour branch above first closes it in this same transaction.
       and a.status <> 'approved'
       and a.reviewed_at <= p_now
       and a.contact_purged_at is null;
    get diagnostics contacts_purged = row_count;

    update private.member_invitation_requests r
       set email_sha256 = null,
           contact_purged_at = p_now
     where r.status in ('finalized','cancelled')
       and coalesce(r.finalized_at,r.cancelled_at,r.expires_at) <= p_now
       and r.contact_purged_at is null;
    get diagnostics invitation_contacts_purged = row_count;

    delete from private.access_application_audit a
    where a.occurred_at <= p_now - interval '179 days';
    get diagnostics audit_deleted = row_count;

    delete from private.invitation_provisioning_audit a
    where a.occurred_at <= p_now - interval '179 days';
    get diagnostics invitation_audit_deleted = row_count;

    delete from private.access_applications a
    where a.status <> 'pending'
      and coalesce(a.reviewed_at,a.updated_at,a.created_at)
          <= p_now - interval '179 days';
    get diagnostics applications_deleted = row_count;

    delete from private.access_application_rate_buckets b
    where (
        b.scope in ('global_hour','ip_hour')
        and b.window_start <= p_now - interval '2 hours'
    ) or (
        b.scope = 'email_day'
        and b.window_start <= p_now - interval '2 days'
    );
    get diagnostics rate_buckets_deleted = row_count;

    delete from private.sync_event_daily_usage u
    where u.usage_date < (p_now at time zone 'UTC')::date - 7;
    get diagnostics event_usage_deleted = row_count;

    delete from private.organization_sync_daily_usage u
    where u.usage_date < (p_now at time zone 'UTC')::date - 7;
    get diagnostics organization_sync_daily_usage_deleted = row_count;

    delete from private.device_session_revocation_audit a
    where a.revoked_at <= p_now - interval '180 days';
    get diagnostics device_session_revocation_audit_deleted = row_count;

    -- Open reports are the live administrator repair queue.  Retaining them
    -- avoids silently losing an unresolved poison-record incident; only
    -- terminal reports age out at the documented 180-day boundary.
    delete from private.sync_event_quarantine_reports q
    where q.status in ('tombstoned','repaired')
      and q.resolved_at <= p_now - interval '180 days';
    get diagnostics sync_event_quarantine_reports_deleted = row_count;

    return jsonb_build_object(
        'expired_invitations',expired_invitations,
        'expired_memberships',expired_memberships,
        'stale_approvals',stale_approvals,
        'pending_deleted',pending_deleted,
        'contacts_purged',contacts_purged,
        'invitation_contacts_purged',invitation_contacts_purged,
        'audit_deleted',audit_deleted,
        'invitation_audit_deleted',invitation_audit_deleted,
        'applications_deleted',applications_deleted,
        'rate_buckets_deleted',rate_buckets_deleted,
        'event_usage_deleted',event_usage_deleted,
        'organization_sync_daily_usage_deleted',
            organization_sync_daily_usage_deleted,
        'device_session_revocation_audit_deleted',
            device_session_revocation_audit_deleted,
        'sync_event_quarantine_reports_deleted',
            sync_event_quarantine_reports_deleted
    );
end;
$$;
revoke all on function private.enforce_sync_event_daily_quota()
    from public, anon, authenticated, service_role;
revoke all on function public.pull_sync_events(uuid,bigint,integer)
    from public, anon, authenticated;
revoke all on function public.revoke_current_device_session()
    from public, anon, authenticated;
revoke all on function public.report_sync_event_quarantine(
    uuid,bigint,uuid,uuid,uuid,text
) from public, anon, authenticated;
revoke all on function public.list_sync_quarantine_reports(uuid,integer)
    from public, anon, authenticated;
revoke all on function public.admin_tombstone_quarantined_record(uuid,jsonb)
    from public, anon, authenticated;
revoke all on function public.admin_mark_quarantine_repaired(uuid)
    from public, anon, authenticated;

grant execute on function public.pull_sync_events(uuid,bigint,integer)
    to authenticated;
grant execute on function public.revoke_current_device_session()
    to authenticated;
grant execute on function public.report_sync_event_quarantine(
    uuid,bigint,uuid,uuid,uuid,text
) to authenticated;
grant execute on function public.list_sync_quarantine_reports(uuid,integer)
    to authenticated;
grant execute on function public.admin_tombstone_quarantined_record(uuid,jsonb)
    to authenticated;
grant execute on function public.admin_mark_quarantine_repaired(uuid)
    to authenticated;

commit;
