-- Make a first ciphertext snapshot resumable without weakening the normal
-- "snapshot only into an empty organization" rule.  The server stores only
-- record/version identities and content hashes; plaintext never crosses this
-- boundary.
begin;

create table private.snapshot_imports (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null
        references public.organizations(id) on delete cascade,
    expected_count bigint not null check (expected_count >= 0),
    accepted_count bigint not null default 0 check (
        accepted_count >= 0 and accepted_count <= expected_count
    ),
    manifest_hash text not null check (manifest_hash ~ '^[0-9a-f]{64}$'),
    status text not null default 'staging' check (
        status in ('staging','completed','aborted')
    ),
    created_by uuid not null references auth.users(id),
    created_at timestamptz not null default now(),
    completed_at timestamptz,
    unique (id, organization_id)
);

create unique index snapshot_imports_one_staging_per_org
    on private.snapshot_imports(organization_id)
    where status = 'staging';

create table private.snapshot_import_items (
    import_id uuid not null,
    organization_id uuid not null,
    event_id uuid not null,
    record_id uuid not null,
    version_id uuid not null,
    content_hash text not null check (content_hash ~ '^[0-9a-f]{64}$'),
    accepted_at timestamptz not null default now(),
    primary key (import_id, record_id),
    unique (import_id, event_id),
    unique (import_id, version_id),
    foreign key (import_id, organization_id)
        references private.snapshot_imports(id, organization_id)
        on delete cascade,
    foreign key (organization_id, record_id, version_id)
        references public.record_versions(
            organization_id, record_id, version_id
        )
);

revoke all on table
    private.snapshot_imports,
    private.snapshot_import_items
from public, anon, authenticated;

create or replace function public.begin_snapshot_import(
    organization_id uuid,
    expected_count bigint,
    manifest_hash text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    active_import private.snapshot_imports%rowtype;
    remote_has_heads boolean;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    if not private.is_org_owner(organization_id) then
        raise exception 'snapshot import requires active owner';
    end if;
    if expected_count is null or expected_count < 0 then
        raise exception 'invalid snapshot expected count';
    end if;
    if manifest_hash is null
       or manifest_hash !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid snapshot manifest hash';
    end if;

    -- Serialize session creation with record pushes and key rotation.
    perform 1
    from public.organizations o
    where o.id = begin_snapshot_import.organization_id
    for update;
    if not found then
        raise exception 'organization not found';
    end if;
    if exists (
        select 1
        from public.key_rotations r
        where r.organization_id = begin_snapshot_import.organization_id
          and r.status = 'staging'
    ) then
        raise exception 'key rotation in progress';
    end if;

    -- This branch intentionally precedes the remote-head check: an
    -- interrupted import has already created some heads and must be resumable.
    select i.* into active_import
    from private.snapshot_imports i
    where i.organization_id = begin_snapshot_import.organization_id
      and i.status = 'staging'
    for update;
    if found then
        if active_import.expected_count
               <> begin_snapshot_import.expected_count
           or active_import.manifest_hash
               <> lower(begin_snapshot_import.manifest_hash) then
            raise exception 'snapshot import manifest mismatch';
        end if;
        return jsonb_build_object(
            'import_id',active_import.id,
            'organization_id',active_import.organization_id,
            'expected_count',active_import.expected_count,
            'accepted_count',active_import.accepted_count,
            'manifest_hash',active_import.manifest_hash,
            'status',active_import.status,
            'resumed',true
        );
    end if;

    -- A completed retry with the same manifest is also idempotent.  It cannot
    -- be reopened or replaced by a different manifest.
    select i.* into active_import
    from private.snapshot_imports i
    where i.organization_id = begin_snapshot_import.organization_id
      and i.status = 'completed'
    order by i.completed_at desc nulls last, i.created_at desc
    limit 1;
    if found
       and active_import.expected_count
               = begin_snapshot_import.expected_count
       and active_import.manifest_hash
               = lower(begin_snapshot_import.manifest_hash) then
        return jsonb_build_object(
            'import_id',active_import.id,
            'organization_id',active_import.organization_id,
            'expected_count',active_import.expected_count,
            'accepted_count',active_import.accepted_count,
            'manifest_hash',active_import.manifest_hash,
            'status',active_import.status,
            'resumed',true
        );
    end if;

    select exists (
        select 1 from public.record_heads h
        where h.organization_id = begin_snapshot_import.organization_id
    ) into remote_has_heads;
    if remote_has_heads then
        raise exception 'snapshot import requires empty organization';
    end if;

    insert into private.snapshot_imports(
        organization_id,expected_count,manifest_hash,created_by
    ) values (
        begin_snapshot_import.organization_id,
        begin_snapshot_import.expected_count,
        lower(begin_snapshot_import.manifest_hash),
        actor
    )
    returning * into active_import;

    return jsonb_build_object(
        'import_id',active_import.id,
        'organization_id',active_import.organization_id,
        'expected_count',active_import.expected_count,
        'accepted_count',active_import.accepted_count,
        'manifest_hash',active_import.manifest_hash,
        'status',active_import.status,
        'resumed',false
    );
end;
$$;

create or replace function private.capture_snapshot_import_item()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    active_import private.snapshot_imports%rowtype;
    version_hash text;
begin
    -- push_record_event already holds this organization's row FOR SHARE
    -- before it reads or writes record_heads (migration 009).  begin uses
    -- FOR UPDATE, so the two transactions serialize without a lock upgrade
    -- inside this trigger.
    select i.* into active_import
    from private.snapshot_imports i
    where i.organization_id = new.organization_id
      and i.status = 'staging'
    for update;
    if not found and new.operation <> 'snapshot' then
        return new;
    end if;
    if not found then
        raise exception 'active snapshot import required';
    end if;
    if new.operation <> 'snapshot' then
        raise exception 'snapshot import blocks non-snapshot writes';
    end if;
    if new.applied is not true then
        raise exception 'snapshot import requires an applied head';
    end if;
    if not private.is_org_owner(new.organization_id) then
        raise exception 'snapshot import requires active owner';
    end if;
    if active_import.accepted_count >= active_import.expected_count then
        raise exception 'snapshot import capacity exceeded';
    end if;

    select v.content_hash into version_hash
    from public.record_versions v
    where v.organization_id = new.organization_id
      and v.record_id = new.record_id
      and v.version_id = new.version_id;
    if not found then
        raise exception 'snapshot import version not found';
    end if;

    insert into private.snapshot_import_items(
        import_id,organization_id,event_id,record_id,version_id,content_hash
    ) values (
        active_import.id,
        new.organization_id,
        new.event_id,
        new.record_id,
        new.version_id,
        version_hash
    );
    update private.snapshot_imports i
       set accepted_count = i.accepted_count + 1
     where i.id = active_import.id;
    return new;
end;
$$;

drop trigger if exists sync_events_capture_snapshot_import
    on public.sync_events;
create trigger sync_events_capture_snapshot_import
before insert on public.sync_events
for each row execute function private.capture_snapshot_import_item();

create or replace function private.block_rotation_during_snapshot()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    if exists (
        select 1
        from private.snapshot_imports i
        where i.organization_id = new.organization_id
          and i.status = 'staging'
    ) then
        raise exception 'snapshot import in progress';
    end if;
    return new;
end;
$$;

drop trigger if exists key_rotations_block_snapshot
    on public.key_rotations;
create trigger key_rotations_block_snapshot
before insert or update on public.key_rotations
for each row execute function private.block_rotation_during_snapshot();

create or replace function public.complete_snapshot_import(import_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    target private.snapshot_imports%rowtype;
    item_count bigint;
    head_count bigint;
    calculated_manifest text;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;

    select i.* into target
    from private.snapshot_imports i
    where i.id = complete_snapshot_import.import_id
    for update;
    if not found then
        raise exception 'snapshot import not found';
    end if;
    if not private.is_org_owner(target.organization_id) then
        raise exception 'snapshot import requires active owner';
    end if;
    if target.status = 'completed' then
        return jsonb_build_object(
            'import_id',target.id,
            'organization_id',target.organization_id,
            'expected_count',target.expected_count,
            'accepted_count',target.accepted_count,
            'manifest_hash',target.manifest_hash,
            'status',target.status,
            'resumed',true
        );
    end if;
    if target.status <> 'staging' then
        raise exception 'snapshot import is not staging';
    end if;
    if target.accepted_count <> target.expected_count then
        raise exception 'snapshot import is incomplete';
    end if;

    select
        count(*),
        encode(
            extensions.digest(
                convert_to(
                    coalesce(
                        string_agg(
                            i.record_id::text || ':' ||
                            i.version_id::text || ':' ||
                            i.content_hash,
                            E'\n'
                            order by
                                i.record_id::text,
                                i.version_id::text,
                                i.content_hash
                        ),
                        ''
                    ),
                    'UTF8'
                ),
                'sha256'
            ),
            'hex'
        )
    into item_count,calculated_manifest
    from private.snapshot_import_items i
    where i.import_id = target.id;

    if item_count <> target.expected_count then
        raise exception 'snapshot import item count mismatch';
    end if;
    if calculated_manifest <> target.manifest_hash then
        raise exception 'snapshot import manifest hash mismatch';
    end if;
    select count(*) into head_count
    from public.record_heads h
    where h.organization_id = target.organization_id;
    if head_count <> target.expected_count then
        raise exception 'snapshot import head count mismatch';
    end if;
    if exists (
        select 1
        from public.record_heads h
        left join private.snapshot_import_items i
          on i.import_id = target.id
         and i.organization_id = h.organization_id
         and i.record_id = h.record_id
         and i.version_id = h.head_version_id
        where h.organization_id = target.organization_id
          and i.import_id is null
    ) then
        raise exception 'snapshot import head set mismatch';
    end if;

    update private.snapshot_imports i
       set status='completed',completed_at=now()
     where i.id=target.id
     returning * into target;

    return jsonb_build_object(
        'import_id',target.id,
        'organization_id',target.organization_id,
        'expected_count',target.expected_count,
        'accepted_count',target.accepted_count,
        'manifest_hash',target.manifest_hash,
        'status',target.status,
        'resumed',false
    );
end;
$$;

create or replace function public.abort_snapshot_import(import_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    target private.snapshot_imports%rowtype;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    select i.* into target
    from private.snapshot_imports i
    where i.id = abort_snapshot_import.import_id
    for update;
    if not found then
        raise exception 'snapshot import not found';
    end if;
    if not private.is_org_owner(target.organization_id) then
        raise exception 'snapshot import requires active owner';
    end if;
    if target.status = 'aborted' then
        return jsonb_build_object(
            'import_id',target.id,
            'organization_id',target.organization_id,
            'expected_count',target.expected_count,
            'accepted_count',target.accepted_count,
            'manifest_hash',target.manifest_hash,
            'status',target.status
        );
    end if;
    if target.status <> 'staging' then
        raise exception 'snapshot import is not staging';
    end if;
    if target.accepted_count <> 0 or exists (
        select 1 from private.snapshot_import_items i
        where i.import_id = target.id
    ) then
        raise exception 'accepted snapshot import cannot be aborted';
    end if;
    if exists (
        select 1 from public.record_heads h
        where h.organization_id = target.organization_id
    ) then
        raise exception 'nonempty snapshot import cannot be aborted';
    end if;
    update private.snapshot_imports i
       set status='aborted'
     where i.id=target.id
     returning * into target;
    return jsonb_build_object(
        'import_id',target.id,
        'organization_id',target.organization_id,
        'expected_count',target.expected_count,
        'accepted_count',target.accepted_count,
        'manifest_hash',target.manifest_hash,
        'status',target.status
    );
end;
$$;

revoke all on function private.capture_snapshot_import_item()
    from public, anon, authenticated;
revoke all on function private.block_rotation_during_snapshot()
    from public, anon, authenticated;
revoke all on function public.begin_snapshot_import(uuid,bigint,text)
    from public, anon, authenticated;
revoke all on function public.complete_snapshot_import(uuid)
    from public, anon, authenticated;
revoke all on function public.abort_snapshot_import(uuid)
    from public, anon, authenticated;
grant execute on function public.begin_snapshot_import(uuid,bigint,text)
    to authenticated;
grant execute on function public.complete_snapshot_import(uuid)
    to authenticated;
grant execute on function public.abort_snapshot_import(uuid)
    to authenticated;

commit;
