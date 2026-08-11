-- Make the signed object manifest fail closed on every nullable comparison.
-- Migration 012 was applied to an empty Staging project; this additive patch
-- keeps the deployed history immutable.

alter table public.workflow_states
    drop constraint if exists workflow_states_object_manifest_check,
    add constraint workflow_states_object_manifest_check check (
        (
            state in ('pending_approval','signed','recalled')
            and bound_version_id is not null
            and object_manifest_hash is not null
            and object_manifest_hash ~ '^[0-9a-f]{64}$'
            and object_count is not null
            and object_count >= 0
        )
        or (
            state in ('draft','editing')
            and bound_version_id is null
            and object_manifest_hash is null
            and object_count is null
        )
    );

create or replace function private.guard_signed_object_manifest_not_null()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    current_head_version_id uuid;
    manifest record;
begin
    if new.state <> 'signed' then
        return new;
    end if;
    select h.head_version_id into current_head_version_id
    from public.record_heads h
    where h.organization_id = new.organization_id
      and h.record_id = new.record_id;
    if not found or current_head_version_id is null then
        raise exception 'current record head required';
    end if;
    select * into manifest
    from private.current_object_manifest(
        new.organization_id,new.record_id,current_head_version_id
    );
    if manifest.physical_count is distinct from manifest.object_count then
        raise exception 'workflow object metadata/storage mismatch';
    end if;
    if old.bound_version_id is distinct from current_head_version_id
       or old.object_count is distinct from manifest.object_count
       or old.object_manifest_hash
              is distinct from manifest.object_manifest_hash then
        raise exception 'pending approval object manifest changed';
    end if;
    return new;
end;
$$;

drop trigger if exists guard_signed_object_manifest_not_null
    on public.workflow_states;
create trigger guard_signed_object_manifest_not_null
before update on public.workflow_states
for each row execute function
    private.guard_signed_object_manifest_not_null();

revoke all on function private.guard_signed_object_manifest_not_null()
    from public, anon, authenticated;

alter table private.encrypted_object_delete_requests
    add column if not exists storage_deleted_at timestamptz,
    add column if not exists metadata_deleted_at timestamptz,
    add column if not exists orphaned_at timestamptz,
    add column if not exists cleanup_attempts integer
        not null default 0 check (cleanup_attempts >= 0),
    add column if not exists last_cleanup_attempt_at timestamptz,
    add column if not exists last_cleanup_confirmed_at timestamptz,
    add column if not exists finalized_by uuid
        references auth.users(id);

-- Migration 012 could leave completed rows without the new lifecycle
-- timestamps and could leave one requested ticket per actor. Normalize those
-- rows before validating the stricter object-global state machine.
update private.encrypted_object_delete_requests
   set storage_deleted_at = coalesce(
           storage_deleted_at,completed_at,created_at
       ),
       metadata_deleted_at = coalesce(
           metadata_deleted_at,completed_at,created_at
       ),
       finalized_by = coalesce(finalized_by,requested_by)
 where status = 'completed';

with ranked_active_requests as (
    select
        id,
        row_number() over (
            partition by organization_id,object_id
            order by created_at desc,id desc
        ) as active_rank
    from private.encrypted_object_delete_requests
    where status in ('requested','storage_deleted','orphaned')
)
update private.encrypted_object_delete_requests r
   set status = 'cancelled',
       storage_deleted_at = null,
       metadata_deleted_at = null,
       orphaned_at = null,
       completed_at = null,
       finalized_by = null
  from ranked_active_requests ranked
 where r.id = ranked.id
   and ranked.active_rank > 1;

alter table private.encrypted_object_delete_requests
    drop constraint if exists
        encrypted_object_delete_requests_status_check,
    add constraint encrypted_object_delete_requests_status_check
        check (
            status in (
                'requested','storage_deleted','orphaned',
                'completed','cancelled'
            )
        ),
    drop constraint if exists
        encrypted_object_delete_requests_lifecycle_check,
    add constraint encrypted_object_delete_requests_lifecycle_check
        check (
            (
                status = 'requested'
                and storage_deleted_at is null
                and metadata_deleted_at is null
                and orphaned_at is null
                and completed_at is null
            )
            or (
                status = 'storage_deleted'
                and storage_deleted_at is not null
                and orphaned_at is null
                and completed_at is null
            )
            or (
                status = 'orphaned'
                and storage_deleted_at is not null
                and metadata_deleted_at is not null
                and orphaned_at is not null
                and completed_at is null
            )
            or (
                status = 'completed'
                and storage_deleted_at is not null
                and metadata_deleted_at is not null
                and completed_at is not null
            )
            or (
                status = 'cancelled'
                and storage_deleted_at is null
                and metadata_deleted_at is null
                and orphaned_at is null
                and completed_at is null
            )
        );

create unique index
    encrypted_object_delete_requests_one_active_object
on private.encrypted_object_delete_requests(organization_id,object_id)
where status in ('requested','storage_deleted','orphaned');

-- Approval and signing must not race an already-authorized object deletion.
-- transition_workflow and begin_encrypted_object_delete both serialize on the
-- organization/record/workflow locks before this ticket check.
create or replace function private.guard_workflow_transition()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    current_head public.record_heads%rowtype;
    head_content_hash text;
    manifest record;
begin
    if new.state not in (
        'draft','editing','pending_approval','signed','recalled'
    ) then
        raise exception 'invalid workflow state';
    end if;

    if tg_op = 'INSERT' then
        if new.version <> 1
           or new.state not in ('draft','editing') then
            raise exception 'invalid initial workflow transition';
        end if;
        new.bound_version_id := null;
        new.object_manifest_hash := null;
        new.object_count := null;
        return new;
    end if;

    if new.version <> old.version + 1
       or not (
            (
                old.state in ('draft','editing')
                and new.state in ('editing','pending_approval')
            )
            or (
                old.state = 'pending_approval'
                and new.state in ('editing','signed')
            )
            or (
                old.state = 'signed'
                and new.state = 'recalled'
            )
            or (
                old.state = 'recalled'
                and new.state = 'editing'
            )
       ) then
        raise exception 'invalid workflow transition';
    end if;

    if new.state in ('editing','draft') then
        new.bound_version_id := null;
        new.object_manifest_hash := null;
        new.object_count := null;
        return new;
    end if;

    if new.state = 'recalled' then
        new.bound_version_id := old.bound_version_id;
        new.object_manifest_hash := old.object_manifest_hash;
        new.object_count := old.object_count;
        return new;
    end if;

    perform 1
    from public.organizations o
    where o.id = new.organization_id
    for update;
    if not found then
        raise exception 'organization not found';
    end if;
    select h.* into current_head
    from public.record_heads h
    where h.organization_id = new.organization_id
      and h.record_id = new.record_id
    for update;
    if not found or current_head.head_version_id is null then
        raise exception 'current record head required';
    end if;
    select v.content_hash into head_content_hash
    from public.record_versions v
    where v.organization_id = new.organization_id
      and v.record_id = new.record_id
      and v.version_id = current_head.head_version_id;
    if not found
       or head_content_hash is distinct from new.content_hash then
        raise exception 'workflow content hash does not match current head';
    end if;
    select * into manifest
    from private.current_object_manifest(
        new.organization_id,new.record_id,current_head.head_version_id
    );
    if manifest.physical_count
           is distinct from manifest.object_count then
        raise exception 'workflow object metadata/storage mismatch';
    end if;
    if exists (
        select 1
        from private.encrypted_object_delete_requests r
        where r.organization_id = new.organization_id
          and r.record_id = new.record_id
          and r.version_id = current_head.head_version_id
          and r.status in ('requested','storage_deleted','orphaned')
    ) then
        raise exception 'active object deletion blocks workflow approval';
    end if;

    if new.state = 'pending_approval' then
        new.bound_version_id := current_head.head_version_id;
        new.object_manifest_hash := manifest.object_manifest_hash;
        new.object_count := manifest.object_count;
        return new;
    end if;

    if new.state = 'signed' then
        if old.content_hash is distinct from new.content_hash then
            raise exception 'pending approval content hash changed';
        end if;
        if old.bound_version_id is distinct from
               current_head.head_version_id
           or old.object_count is distinct from manifest.object_count
           or old.object_manifest_hash is distinct from
                  manifest.object_manifest_hash then
            raise exception 'pending approval object manifest changed';
        end if;
        if exists (
            select 1
            from public.conflicts c
            where c.organization_id = new.organization_id
              and c.record_id = new.record_id
              and c.status = 'open'
        ) then
            raise exception 'open conflict blocks signing';
        end if;
        new.bound_version_id := old.bound_version_id;
        new.object_manifest_hash := old.object_manifest_hash;
        new.object_count := old.object_count;
        return new;
    end if;
    raise exception 'invalid workflow transition';
end;
$$;

-- A workflow row represents only the current state. Preserve every signed
-- ciphertext version and its exact object set independently so recall and a
-- later editing cycle can never erase the publication binding.
create table private.signed_publication_versions (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null,
    record_id uuid not null,
    record_version_id uuid not null,
    workflow_version bigint not null check (workflow_version > 0),
    content_hash text not null
        check (content_hash ~ '^[0-9a-f]{64}$'),
    object_manifest_hash text not null
        check (object_manifest_hash ~ '^[0-9a-f]{64}$'),
    object_count bigint not null check (object_count >= 0),
    signed_by uuid not null references auth.users(id),
    signed_at timestamptz not null default clock_timestamp(),
    unique (organization_id,id),
    unique (organization_id,record_id,workflow_version),
    unique (
        organization_id,id,record_id,record_version_id
    ),
    foreign key (organization_id,record_id,record_version_id)
        references public.record_versions(
            organization_id,record_id,version_id
        )
);

create table private.signed_publication_objects (
    publication_id uuid not null,
    organization_id uuid not null,
    record_id uuid not null,
    record_version_id uuid not null,
    object_id uuid not null,
    storage_path text not null,
    ciphertext_sha256 text not null
        check (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
    primary key (publication_id,object_id),
    unique (publication_id,storage_path),
    foreign key (
        organization_id,publication_id,record_id,record_version_id
    ) references private.signed_publication_versions(
        organization_id,id,record_id,record_version_id
    ),
    foreign key (organization_id,object_id)
        references public.encrypted_objects(organization_id,id)
);

create index signed_publication_objects_by_object
    on private.signed_publication_objects(organization_id,object_id);
create index signed_publication_objects_by_path
    on private.signed_publication_objects(organization_id,storage_path);

revoke all on table private.signed_publication_versions
    from public, anon, authenticated;
revoke all on table private.signed_publication_objects
    from public, anon, authenticated;

do $$
begin
    if exists (
        select 1
        from public.workflow_states w
        where w.state in ('signed','recalled')
    )
       or exists (
           select 1
           from public.audit_chain a
           where a.event_type = 'workflow:signed'
    ) then
        raise exception
            'existing signed workflow history requires explicit migration';
    end if;
end;
$$;

create or replace function private.capture_signed_publication()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    publication_id uuid;
    captured_object_count bigint;
begin
    if new.state <> 'signed'
       or old.state <> 'pending_approval' then
        return new;
    end if;
    if new.bound_version_id is null
       or new.object_manifest_hash is null
       or new.object_count is null then
        raise exception 'signed publication binding required';
    end if;
    insert into private.signed_publication_versions(
        organization_id,record_id,record_version_id,
        workflow_version,content_hash,object_manifest_hash,
        object_count,signed_by,signed_at
    ) values (
        new.organization_id,new.record_id,new.bound_version_id,
        new.version,new.content_hash,new.object_manifest_hash,
        new.object_count,new.updated_by,new.updated_at
    )
    returning id into publication_id;
    insert into private.signed_publication_objects(
        publication_id,organization_id,record_id,record_version_id,
        object_id,storage_path,ciphertext_sha256
    )
    select
        publication_id,o.organization_id,o.record_id,o.version_id,
        o.id,o.storage_path,o.ciphertext_sha256
    from public.encrypted_objects o
    where o.organization_id = new.organization_id
      and o.record_id = new.record_id
      and o.version_id = new.bound_version_id;
    get diagnostics captured_object_count = row_count;
    if captured_object_count is distinct from new.object_count then
        raise exception 'signed publication object snapshot changed';
    end if;
    return new;
end;
$$;

drop trigger if exists capture_signed_publication
    on public.workflow_states;
create trigger capture_signed_publication
after update on public.workflow_states
for each row execute function private.capture_signed_publication();

revoke all on function private.capture_signed_publication()
    from public, anon, authenticated;

create or replace function private.guard_encrypted_object_mutation()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    target_organization_id uuid;
    request_text text;
    request_id uuid;
begin
    if tg_op = 'INSERT' then
        target_organization_id := new.organization_id;
    else
        target_organization_id := old.organization_id;
    end if;
    perform 1
    from public.organizations org
    where org.id = target_organization_id
    for share;
    if not found then
        raise exception 'organization not found';
    end if;
    if tg_op = 'INSERT' then
        if exists (
            select 1
            from private.encrypted_object_delete_requests r
            where r.organization_id = new.organization_id
              and (
                  r.object_id = new.id
                  or r.storage_path = new.storage_path
              )
              and (
                  r.status <> 'cancelled'
                  or r.metadata_deleted_at is not null
              )
        ) then
            raise exception 'deleted object identifiers cannot be reused';
        end if;
        if exists (
            select 1
            from public.workflow_states w
            where w.organization_id = new.organization_id
              and w.record_id = new.record_id
              and w.bound_version_id = new.version_id
              and w.state in (
                  'pending_approval','signed','recalled'
              )
        ) then
            raise exception 'protected workflow objects are immutable';
        end if;
        if exists (
            select 1
            from private.signed_publication_versions p
            where p.organization_id = new.organization_id
              and p.record_id = new.record_id
              and p.record_version_id = new.version_id
        ) then
            raise exception 'historically signed versions are immutable';
        end if;
        return new;
    end if;
    if tg_op = 'UPDATE' then
        raise exception 'encrypted object metadata is immutable';
    end if;
    if exists (
        select 1
        from public.workflow_states w
        where w.organization_id = old.organization_id
          and w.record_id = old.record_id
          and w.bound_version_id = old.version_id
          and w.state in ('pending_approval','signed','recalled')
    ) then
        raise exception 'protected workflow objects cannot be deleted';
    end if;
    if exists (
        select 1
        from private.signed_publication_objects p
        where p.organization_id = old.organization_id
          and p.object_id = old.id
    ) then
        raise exception 'historically signed objects cannot be deleted';
    end if;
    request_text := current_setting(
        'defense_tracker.object_delete_request',true
    );
    if request_text is null or request_text = '' then
        raise exception 'object delete ticket required';
    end if;
    begin
        request_id := request_text::uuid;
    exception when invalid_text_representation then
        raise exception 'invalid object delete ticket';
    end;
    if not exists (
        select 1
        from private.encrypted_object_delete_requests r
        where r.id = request_id
          and r.organization_id = old.organization_id
          and r.record_id = old.record_id
          and r.version_id = old.version_id
          and r.object_id = old.id
          and r.storage_path = old.storage_path
          and r.ciphertext_sha256 = old.ciphertext_sha256
          and (
              r.requested_by = (select auth.uid())
              or r.finalized_by = (select auth.uid())
          )
          and r.status = 'storage_deleted'
          and r.storage_deleted_at is not null
    ) then
        raise exception 'valid object delete ticket required';
    end if;
    return old;
end;
$$;

create or replace function public.begin_encrypted_object_delete(
    organization_id uuid,
    object_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    actor_role text;
    object_snapshot public.encrypted_objects%rowtype;
    target_object public.encrypted_objects%rowtype;
    current_state public.workflow_states%rowtype;
    active_request private.encrypted_object_delete_requests%rowtype;
    request_row private.encrypted_object_delete_requests%rowtype;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    perform 1
    from public.organizations org
    where org.id = begin_encrypted_object_delete.organization_id
    for update;
    if not found then
        raise exception 'object not found or access denied';
    end if;
    select m.role into actor_role
    from public.memberships m
    where m.organization_id =
              begin_encrypted_object_delete.organization_id
      and m.user_id = actor
      and m.status = 'active';
    if actor_role is null
       or actor_role not in ('owner','admin') then
        raise exception 'object not found or access denied';
    end if;
    select o.* into object_snapshot
    from public.encrypted_objects o
    where o.organization_id =
              begin_encrypted_object_delete.organization_id
      and o.id = begin_encrypted_object_delete.object_id;
    if not found then
        raise exception 'object not found or access denied';
    end if;
    perform 1
    from public.record_heads h
    where h.organization_id = object_snapshot.organization_id
      and h.record_id = object_snapshot.record_id
    for update;
    if not found then
        raise exception 'record head not found';
    end if;
    select w.* into current_state
    from public.workflow_states w
    where w.organization_id = object_snapshot.organization_id
      and w.record_id = object_snapshot.record_id
    for update;
    select o.* into target_object
    from public.encrypted_objects o
    where o.organization_id = object_snapshot.organization_id
      and o.record_id = object_snapshot.record_id
      and o.version_id = object_snapshot.version_id
      and o.id = object_snapshot.id
    for update;
    if not found then
        raise exception 'encrypted object changed';
    end if;
    if current_state.state in ('pending_approval','signed','recalled')
       and current_state.bound_version_id = target_object.version_id then
        raise exception 'protected workflow objects cannot be deleted';
    end if;
    if exists (
        select 1
        from private.signed_publication_objects p
        where p.organization_id = target_object.organization_id
          and p.object_id = target_object.id
    ) then
        raise exception 'historically signed objects cannot be deleted';
    end if;
    if not exists (
        select 1
        from storage.objects s
        where s.bucket_id = 'defense-v9-encrypted'
          and s.name = target_object.storage_path
    ) then
        raise exception 'storage object not found';
    end if;

    begin
        select r.* into active_request
        from private.encrypted_object_delete_requests r
        where r.organization_id = target_object.organization_id
          and r.object_id = target_object.id
          and r.status in ('requested','storage_deleted','orphaned')
        for update nowait;
    exception
        when lock_not_available then
            raise exception 'object deletion already in progress'
                using errcode = '55P03';
    end;
    if found then
        if active_request.status in ('storage_deleted','orphaned') then
            raise exception
                'storage delete requires metadata finalize or retry';
        end if;
        if active_request.requested_by <> actor
           and active_request.expires_at > clock_timestamp()
           and exists (
               select 1
               from public.memberships m
               where m.organization_id = target_object.organization_id
                 and m.user_id = active_request.requested_by
                 and m.status = 'active'
                 and m.role in ('owner','admin')
           ) then
            raise exception 'active object delete ticket exists';
        end if;
        update private.encrypted_object_delete_requests r
           set status = 'cancelled'
         where r.id = active_request.id;
    end if;

    insert into private.encrypted_object_delete_requests(
        organization_id,record_id,version_id,object_id,storage_path,
        ciphertext_sha256,requested_by,expires_at
    ) values (
        target_object.organization_id,target_object.record_id,
        target_object.version_id,target_object.id,
        target_object.storage_path,target_object.ciphertext_sha256,
        actor,clock_timestamp() + interval '5 minutes'
    )
    returning * into request_row;
    perform private.append_object_audit(
        target_object.organization_id,
        target_object.record_id,
        'object_delete_requested:' || request_row.id::text,
        actor,
        target_object.ciphertext_sha256
    );
    return jsonb_build_object(
        'request_id',request_row.id,
        'organization_id',request_row.organization_id,
        'record_id',request_row.record_id,
        'version_id',request_row.version_id,
        'object_id',request_row.object_id,
        'storage_path',request_row.storage_path,
        'ciphertext_sha256',request_row.ciphertext_sha256,
        'expires_at',request_row.expires_at
    );
end;
$$;

create or replace function public.cancel_encrypted_object_delete(
    request_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    actor_role text;
    request_snapshot private.encrypted_object_delete_requests%rowtype;
    target_request private.encrypted_object_delete_requests%rowtype;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    select r.* into request_snapshot
    from private.encrypted_object_delete_requests r
    where r.id = cancel_encrypted_object_delete.request_id
      and exists (
          select 1
          from public.memberships m
          where m.organization_id = r.organization_id
            and m.user_id = actor
            and m.status = 'active'
            and m.role in ('owner','admin')
      );
    if not found then
        raise exception 'object delete request not found';
    end if;
    perform 1
    from public.organizations org
    where org.id = request_snapshot.organization_id
    for update;
    if not found then
        raise exception 'object delete request not found';
    end if;
    select m.role into actor_role
    from public.memberships m
    where m.organization_id = request_snapshot.organization_id
      and m.user_id = actor
      and m.status = 'active';
    if actor_role is null
       or actor_role not in ('owner','admin') then
        raise exception 'object delete request not found';
    end if;
    begin
        select r.* into target_request
        from private.encrypted_object_delete_requests r
        where r.id = request_snapshot.id
          and r.organization_id = request_snapshot.organization_id
          and r.record_id = request_snapshot.record_id
          and r.version_id = request_snapshot.version_id
          and r.object_id = request_snapshot.object_id
          and r.storage_path = request_snapshot.storage_path
          and r.ciphertext_sha256 = request_snapshot.ciphertext_sha256
        for update nowait;
    exception
        when lock_not_available then
            raise exception 'object deletion already in progress'
                using errcode = '55P03';
    end;
    if not found then
        raise exception 'object delete request not found';
    end if;
    if target_request.status <> 'requested'
       or target_request.storage_deleted_at is not null
       or target_request.metadata_deleted_at is not null
       or target_request.orphaned_at is not null
       or target_request.completed_at is not null
       or target_request.cleanup_attempts <> 0
       or target_request.last_cleanup_attempt_at is not null
       or target_request.last_cleanup_confirmed_at is not null then
        raise exception 'only untouched requested deletion can be cancelled';
    end if;
    update private.encrypted_object_delete_requests r
       set status = 'cancelled'
     where r.id = target_request.id
     returning * into target_request;
    perform private.append_object_audit(
        target_request.organization_id,
        target_request.record_id,
        'object_delete_cancelled:' || target_request.id::text,
        actor,
        target_request.ciphertext_sha256
    );
    return jsonb_build_object(
        'request_id',target_request.id,
        'organization_id',target_request.organization_id,
        'record_id',target_request.record_id,
        'version_id',target_request.version_id,
        'object_id',target_request.object_id,
        'storage_path',target_request.storage_path,
        'ciphertext_sha256',target_request.ciphertext_sha256,
        'status','cancelled'
    );
end;
$$;

create or replace function private.can_delete_encrypted_storage_object(
    object_path text
)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    path_organization_id uuid;
    actor_role text;
    current_state public.workflow_states%rowtype;
    request_snapshot private.encrypted_object_delete_requests%rowtype;
    target_request private.encrypted_object_delete_requests%rowtype;
    target_object public.encrypted_objects%rowtype;
    transaction_request text;
    cleanup_only boolean := false;
begin
    if actor is null then
        return false;
    end if;
    if not storage.allow_any_operation(
        array['object.delete','object.delete_many']
    ) then
        return false;
    end if;
    path_organization_id := private.path_org_uuid(object_path);
    if path_organization_id is null then
        return false;
    end if;
    -- Read without a row lock first, then serialize only on the path-bound
    -- ticket. Record/workflow/object rows are never locked by this Storage RLS
    -- helper because its transaction spans the external blob delete.
    select r.* into request_snapshot
    from private.encrypted_object_delete_requests r
    where r.organization_id = path_organization_id
      and r.storage_path = object_path
      and r.status in (
          'requested','storage_deleted','orphaned','completed'
      )
      and (
          r.status <> 'completed'
          or r.metadata_deleted_at is not null
    )
    order by r.created_at desc,r.id desc
    limit 1;
    if not found then
        return false;
    end if;
    select m.role into actor_role
    from public.memberships m
    where m.organization_id = path_organization_id
      and m.user_id = actor
      and m.status = 'active';
    if actor_role is null
       or actor_role not in ('owner','admin') then
        return false;
    end if;
    select r.* into target_request
    from private.encrypted_object_delete_requests r
    where r.id = request_snapshot.id
      and r.organization_id = request_snapshot.organization_id
      and r.record_id = request_snapshot.record_id
      and r.version_id = request_snapshot.version_id
      and r.object_id = request_snapshot.object_id
      and r.storage_path = request_snapshot.storage_path
      and r.ciphertext_sha256 = request_snapshot.ciphertext_sha256
      and r.status in (
          'requested','storage_deleted','orphaned','completed'
      )
      and (
          r.status <> 'completed'
          or r.metadata_deleted_at is not null
      )
    for update;
    if not found then
        return false;
    end if;
    -- Membership may have been revoked while waiting on a lock.
    select m.role into actor_role
    from public.memberships m
    where m.organization_id = target_request.organization_id
      and m.user_id = actor
      and m.status = 'active';
    if actor_role is null
       or actor_role not in ('owner','admin') then
        return false;
    end if;
    cleanup_only := (
        target_request.status in ('orphaned','completed')
        or target_request.metadata_deleted_at is not null
    );
    if cleanup_only then
        if exists (
            select 1
            from public.encrypted_objects o
            where o.organization_id = target_request.organization_id
              and (
                  o.id = target_request.object_id
                  or o.storage_path = target_request.storage_path
              )
        ) then
            return false;
        end if;
    else
        select w.* into current_state
        from public.workflow_states w
        where w.organization_id = target_request.organization_id
          and w.record_id = target_request.record_id;
        if not found then
            return false;
        end if;
        select o.* into target_object
        from public.encrypted_objects o
        where o.organization_id = target_request.organization_id
          and o.record_id = target_request.record_id
          and o.version_id = target_request.version_id
          and o.id = target_request.object_id
          and o.storage_path = target_request.storage_path
          and o.ciphertext_sha256 = target_request.ciphertext_sha256;
        if not found then
            return false;
        end if;
        if current_state.state in (
            'pending_approval','signed','recalled'
        )
           and current_state.bound_version_id =
                   target_request.version_id then
            return false;
        end if;
    end if;
    if exists (
        select 1
        from private.signed_publication_objects p
        where p.organization_id = target_request.organization_id
          and p.object_id = target_request.object_id
    ) then
        return false;
    end if;
    if target_request.status = 'completed' then
        transaction_request := current_setting(
            'defense_tracker.storage_delete_request',true
        );
        if transaction_request = target_request.id::text then
            return true;
        end if;
        perform set_config(
            'defense_tracker.storage_delete_request',
            target_request.id::text,
            true
        );
        update private.encrypted_object_delete_requests r
           set cleanup_attempts = r.cleanup_attempts + 1,
               last_cleanup_attempt_at = clock_timestamp()
         where r.id = target_request.id
         returning * into target_request;
        return true;
    end if;
    if target_request.status = 'storage_deleted' then
        transaction_request := current_setting(
            'defense_tracker.storage_delete_request',true
        );
        return transaction_request = target_request.id::text;
    end if;
    if target_request.status = 'requested'
       and target_request.expires_at <= clock_timestamp() then
        return false;
    end if;
    if target_request.status in ('requested','orphaned') then
        update private.encrypted_object_delete_requests r
           set status = 'storage_deleted',
               storage_deleted_at = clock_timestamp(),
               orphaned_at = null,
               cleanup_attempts = r.cleanup_attempts + 1,
               last_cleanup_attempt_at = clock_timestamp()
         where r.id = target_request.id
         returning * into target_request;
        perform set_config(
            'defense_tracker.storage_delete_request',
            target_request.id::text,
            true
        );
    end if;
    return true;
end;
$$;

create or replace function private.can_insert_encrypted_storage_object(
    object_path text
)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    path_organization_id uuid;
    target_object public.encrypted_objects%rowtype;
begin
    if actor is null then
        return false;
    end if;
    path_organization_id := private.path_org_uuid(object_path);
    if path_organization_id is null then
        return false;
    end if;
    if not exists (
        select 1
        from public.memberships m
        where m.organization_id = path_organization_id
          and m.user_id = actor
          and m.status = 'active'
    ) then
        return false;
    end if;
    select o.* into target_object
    from public.encrypted_objects o
    where o.organization_id = path_organization_id
      and o.storage_path = object_path;
    if not found then
        return false;
    end if;
    if exists (
        select 1
        from public.workflow_states w
        where w.organization_id = target_object.organization_id
          and w.record_id = target_object.record_id
          and w.bound_version_id = target_object.version_id
          and w.state in ('pending_approval','signed','recalled')
    ) then
        return false;
    end if;
    if exists (
        select 1
        from private.signed_publication_objects p
        where p.organization_id = target_object.organization_id
          and p.object_id = target_object.id
    ) then
        return false;
    end if;
    if exists (
        select 1
        from private.encrypted_object_delete_requests r
        where r.organization_id = target_object.organization_id
          and r.record_id = target_object.record_id
          and r.version_id = target_object.version_id
          and r.object_id = target_object.id
          and r.storage_path = target_object.storage_path
          and r.ciphertext_sha256 =
                  target_object.ciphertext_sha256
          and (
              r.status <> 'cancelled'
              or r.metadata_deleted_at is not null
          )
    ) then
        return false;
    end if;
    return true;
end;
$$;

-- SELECT is also used internally by Storage for DELETE preflight/RETURNING.
-- Keep this helper side-effect free: the DELETE policy below remains the only
-- place that advances a ticket, while this policy only proves that the caller
-- is an active Owner/Admin with a path-bound, usable ticket.
create or replace function private.can_select_encrypted_storage_delete(
    object_path text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
    select
        (select auth.uid()) is not null
        and storage.allow_any_operation(
            array['object.delete','object.delete_many']
        )
        and exists (
            select 1
            from public.memberships m
            where m.organization_id = private.path_org_uuid(object_path)
              and m.user_id = (select auth.uid())
              and m.status = 'active'
              and m.role in ('owner','admin')
        )
        and exists (
            select 1
            from private.encrypted_object_delete_requests r
            where r.organization_id = private.path_org_uuid(object_path)
              and r.storage_path = object_path
              and r.status in (
                  'requested','storage_deleted','orphaned','completed'
              )
              and (
                  r.status <> 'requested'
                  or r.expires_at > statement_timestamp()
              )
              and (
                  r.status <> 'completed'
                  or r.metadata_deleted_at is not null
              )
        );
$$;

drop policy if exists v9_storage_insert on storage.objects;
create policy v9_storage_insert on storage.objects
for insert to authenticated with check (
    bucket_id = 'defense-v9-encrypted'
    and private.is_org_member(private.path_org_uuid(name))
    and private.can_insert_encrypted_storage_object(name)
);

-- An upload that passed its preliminary permission check before deletion may
-- finish later. Once business metadata is finalized away, this policy makes
-- any such orphaned ciphertext unreadable while an Owner/Admin retries the
-- physical delete. No custom trigger is attached to Supabase-managed tables.
drop policy if exists v9_storage_select on storage.objects;
drop policy if exists v9_storage_download_select on storage.objects;
drop policy if exists v9_storage_upload_return_select on storage.objects;
drop policy if exists v9_storage_delete_internal_select on storage.objects;

-- Only authenticated object reads are downloads. Listing, native signed URL
-- creation, image transforms, and signed GET issuance are deliberately absent.
create policy v9_storage_download_select on storage.objects
for select to authenticated using (
    bucket_id = 'defense-v9-encrypted'
    and storage.allow_any_operation(
        array[
            'object.get_authenticated_info',
            'object.get_authenticated'
        ]
    )
    and private.is_org_member(private.path_org_uuid(name))
    and exists (
        select 1
        from public.encrypted_objects o
        where o.organization_id = private.path_org_uuid(name)
          and o.storage_path = name
    )
    and not exists (
        select 1
        from private.encrypted_object_delete_requests r
        where r.organization_id = private.path_org_uuid(name)
          and r.storage_path = name
          and (
              r.status in (
                  'storage_deleted','orphaned','completed'
              )
              or r.metadata_deleted_at is not null
          )
    )
);

-- Current Storage uploads use INSERT ... RETURNING. Mirror the immutable
-- upload authorization for that operation only; signed uploads and upserts
-- remain disabled because every ciphertext update must use a new path.
create policy v9_storage_upload_return_select on storage.objects
for select to authenticated using (
    bucket_id = 'defense-v9-encrypted'
    and storage.allow_any_operation(array['object.upload'])
    and private.is_org_member(private.path_org_uuid(name))
    and private.can_insert_encrypted_storage_object(name)
);

-- DELETE may perform an internal SELECT/RETURNING under its own operation.
-- This policy reveals nothing to download/list/sign operations and does not
-- mutate ticket state, so policy evaluation order cannot reverse itself.
create policy v9_storage_delete_internal_select on storage.objects
for select to authenticated using (
    bucket_id = 'defense-v9-encrypted'
    and storage.allow_any_operation(
        array['object.delete','object.delete_many']
    )
    and private.can_select_encrypted_storage_delete(name)
);

create or replace function public.finalize_encrypted_object_delete(
    request_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    actor_role text;
    request_snapshot private.encrypted_object_delete_requests%rowtype;
    target_request private.encrypted_object_delete_requests%rowtype;
    target_object public.encrypted_objects%rowtype;
    current_state public.workflow_states%rowtype;
    metadata_exists boolean := false;
    storage_present boolean := false;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    select r.* into request_snapshot
    from private.encrypted_object_delete_requests r
    where r.id = finalize_encrypted_object_delete.request_id
      and exists (
          select 1
          from public.memberships m
          where m.organization_id = r.organization_id
            and m.user_id = actor
            and m.status = 'active'
            and m.role in ('owner','admin')
      );
    if not found then
        raise exception 'object delete request not found';
    end if;
    perform 1
    from public.organizations org
    where org.id = request_snapshot.organization_id
    for update;
    if not found then
        raise exception 'object delete request not found';
    end if;
    select m.role into actor_role
    from public.memberships m
    where m.organization_id = request_snapshot.organization_id
      and m.user_id = actor
      and m.status = 'active';
    if actor_role is null
       or actor_role not in ('owner','admin') then
        raise exception 'object delete request not found';
    end if;
    if request_snapshot.status <> 'completed' then
        perform 1
        from public.record_heads h
        where h.organization_id = request_snapshot.organization_id
          and h.record_id = request_snapshot.record_id
        for update;
        if not found then
            raise exception 'record head not found';
        end if;
        select w.* into current_state
        from public.workflow_states w
        where w.organization_id = request_snapshot.organization_id
          and w.record_id = request_snapshot.record_id
        for update;
        if not found then
            raise exception 'workflow state not found';
        end if;
        select o.* into target_object
        from public.encrypted_objects o
        where o.organization_id = request_snapshot.organization_id
          and o.record_id = request_snapshot.record_id
          and o.version_id = request_snapshot.version_id
          and o.id = request_snapshot.object_id
          and o.storage_path = request_snapshot.storage_path
          and o.ciphertext_sha256 = request_snapshot.ciphertext_sha256
        for update;
        metadata_exists := found;
    end if;
    begin
        select r.* into target_request
        from private.encrypted_object_delete_requests r
        where r.id = request_snapshot.id
          and r.organization_id = request_snapshot.organization_id
          and r.record_id = request_snapshot.record_id
          and r.version_id = request_snapshot.version_id
          and r.object_id = request_snapshot.object_id
          and r.storage_path = request_snapshot.storage_path
          and r.ciphertext_sha256 = request_snapshot.ciphertext_sha256
        for update nowait;
    exception
        when lock_not_available then
            raise exception 'object deletion already in progress'
                using errcode = '55P03';
    end;
    if not found then
        raise exception 'object delete request not found';
    end if;
    if target_request.status = 'completed' then
        select exists (
            select 1
            from storage.objects s
            where s.bucket_id = 'defense-v9-encrypted'
              and s.name = target_request.storage_path
        ) into storage_present;
        if storage_present then
            return jsonb_build_object(
                'request_id',target_request.id,
                'organization_id',target_request.organization_id,
                'record_id',target_request.record_id,
                'version_id',target_request.version_id,
                'object_id',target_request.object_id,
                'storage_path',target_request.storage_path,
                'ciphertext_sha256',target_request.ciphertext_sha256,
                'status','completed',
                'retry_required',true,
                'duplicate',true,
                'cleanup_attempts',target_request.cleanup_attempts,
                'last_cleanup_attempt_at',
                    target_request.last_cleanup_attempt_at,
                'last_cleanup_confirmed_at',
                    target_request.last_cleanup_confirmed_at
            );
        end if;
        if target_request.last_cleanup_attempt_at is not null
           and (
               target_request.last_cleanup_confirmed_at is null
               or target_request.last_cleanup_attempt_at >
                      target_request.last_cleanup_confirmed_at
           ) then
            update private.encrypted_object_delete_requests r
               set last_cleanup_confirmed_at = clock_timestamp(),
                   finalized_by = actor
             where r.id = target_request.id
             returning * into target_request;
            perform private.append_object_audit(
                target_request.organization_id,
                target_request.record_id,
                'object_completed_orphan_cleanup_confirmed:' ||
                    target_request.id::text,
                actor,
                target_request.ciphertext_sha256
            );
        end if;
        return jsonb_build_object(
            'request_id',target_request.id,
            'organization_id',target_request.organization_id,
            'record_id',target_request.record_id,
            'version_id',target_request.version_id,
            'object_id',target_request.object_id,
            'storage_path',target_request.storage_path,
            'ciphertext_sha256',target_request.ciphertext_sha256,
            'status','completed',
            'retry_required',false,
            'duplicate',true,
            'cleanup_attempts',target_request.cleanup_attempts,
            'last_cleanup_attempt_at',
                target_request.last_cleanup_attempt_at,
            'last_cleanup_confirmed_at',
                target_request.last_cleanup_confirmed_at
        );
    end if;
    if target_request.status not in (
        'requested','storage_deleted','orphaned'
    ) then
        raise exception 'object delete request is not finalizable';
    end if;
    if not metadata_exists
       and target_request.metadata_deleted_at is null then
        raise exception 'encrypted object not found';
    end if;
    if metadata_exists then
        if current_state.state in (
            'pending_approval','signed','recalled'
        )
           and current_state.bound_version_id =
                   target_request.version_id then
            raise exception 'protected workflow objects cannot be deleted';
        end if;
        if exists (
            select 1
            from private.signed_publication_objects p
            where p.organization_id = target_request.organization_id
              and p.object_id = target_request.object_id
        ) then
            raise exception 'historically signed objects cannot be deleted';
        end if;
    end if;
    select exists (
        select 1
        from storage.objects s
        where s.bucket_id = 'defense-v9-encrypted'
          and s.name = target_request.storage_path
    ) into storage_present;
    if target_request.status = 'requested' then
        if storage_present then
            raise exception 'storage delete has not completed';
        end if;
        update private.encrypted_object_delete_requests r
           set status = 'storage_deleted',
               storage_deleted_at = coalesce(
                   r.storage_deleted_at,clock_timestamp()
               ),
               finalized_by = actor
         where r.id = target_request.id
         returning * into target_request;
        perform private.append_object_audit(
            target_request.organization_id,
            target_request.record_id,
            'object_storage_deleted_recovered:' ||
                target_request.id::text,
            actor,
            target_request.ciphertext_sha256
        );
    elsif target_request.status = 'orphaned'
          and storage_present then
        update private.encrypted_object_delete_requests r
           set finalized_by = actor
         where r.id = target_request.id
         returning * into target_request;
        return jsonb_build_object(
            'request_id',target_request.id,
            'organization_id',target_request.organization_id,
            'record_id',target_request.record_id,
            'version_id',target_request.version_id,
            'object_id',target_request.object_id,
            'storage_path',target_request.storage_path,
            'ciphertext_sha256',target_request.ciphertext_sha256,
            'status','orphaned',
            'retry_required',true,
            'duplicate',true
        );
    else
        update private.encrypted_object_delete_requests r
           set finalized_by = actor
         where r.id = target_request.id
         returning * into target_request;
    end if;
    if metadata_exists then
        perform set_config(
            'defense_tracker.object_delete_request',
            target_request.id::text,
            true
        );
        delete from public.encrypted_objects o
        where o.organization_id = target_request.organization_id
          and o.id = target_request.object_id;
        update private.encrypted_object_delete_requests r
           set metadata_deleted_at = coalesce(
                   r.metadata_deleted_at,clock_timestamp()
               ),
               finalized_by = actor
         where r.id = target_request.id
         returning * into target_request;
    end if;

    -- Recheck after metadata removal. A previously authorized upload can race
    -- the physical delete, but without public metadata the SELECT policy makes
    -- that ciphertext inaccessible and the ticket remains retryable.
    select exists (
        select 1
        from storage.objects s
        where s.bucket_id = 'defense-v9-encrypted'
          and s.name = target_request.storage_path
    ) into storage_present;
    if storage_present then
        update private.encrypted_object_delete_requests r
           set status = 'orphaned',
               metadata_deleted_at = coalesce(
                   r.metadata_deleted_at,clock_timestamp()
               ),
               orphaned_at = clock_timestamp(),
               completed_at = null,
               finalized_by = actor
         where r.id = target_request.id
         returning * into target_request;
        perform private.append_object_audit(
            target_request.organization_id,
            target_request.record_id,
            'object_storage_orphaned:' || target_request.id::text,
            actor,
            target_request.ciphertext_sha256
        );
        return jsonb_build_object(
            'request_id',target_request.id,
            'organization_id',target_request.organization_id,
            'record_id',target_request.record_id,
            'version_id',target_request.version_id,
            'object_id',target_request.object_id,
            'storage_path',target_request.storage_path,
            'ciphertext_sha256',target_request.ciphertext_sha256,
            'status','orphaned',
            'retry_required',true,
            'duplicate',false
        );
    end if;

    if target_request.last_cleanup_attempt_at is not null
       and (
           target_request.last_cleanup_confirmed_at is null
           or target_request.last_cleanup_attempt_at >
                  target_request.last_cleanup_confirmed_at
       ) then
        update private.encrypted_object_delete_requests r
           set last_cleanup_confirmed_at = clock_timestamp(),
               finalized_by = actor
         where r.id = target_request.id
         returning * into target_request;
        perform private.append_object_audit(
            target_request.organization_id,
            target_request.record_id,
            'object_storage_deleted:' || target_request.id::text,
            actor,
            target_request.ciphertext_sha256
        );
    end if;

    update private.encrypted_object_delete_requests r
       set status = 'completed',
           metadata_deleted_at = coalesce(
               r.metadata_deleted_at,clock_timestamp()
           ),
           completed_at = clock_timestamp(),
           finalized_by = actor
     where r.id = target_request.id
     returning * into target_request;
    perform private.append_object_audit(
        target_request.organization_id,
        target_request.record_id,
        'object_deleted:' || target_request.id::text,
        actor,
        target_request.ciphertext_sha256
    );
    return jsonb_build_object(
        'request_id',target_request.id,
        'organization_id',target_request.organization_id,
        'record_id',target_request.record_id,
        'version_id',target_request.version_id,
        'object_id',target_request.object_id,
        'storage_path',target_request.storage_path,
        'ciphertext_sha256',target_request.ciphertext_sha256,
        'status','completed',
        'retry_required',false,
        'duplicate',false,
        'cleanup_attempts',target_request.cleanup_attempts,
        'last_cleanup_attempt_at',
            target_request.last_cleanup_attempt_at,
        'last_cleanup_confirmed_at',
            target_request.last_cleanup_confirmed_at
    );
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
declare
    actor uuid := (select auth.uid());
    actor_role text;
    result jsonb;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    select m.role into actor_role
    from public.memberships m
    where m.organization_id =
              list_pending_encrypted_object_deletes.organization_id
      and m.user_id = actor
      and m.status = 'active';
    if actor_role is null
       or actor_role not in ('owner','admin') then
        raise exception 'owner or admin role required';
    end if;
    select coalesce(
        jsonb_agg(
            jsonb_build_object(
                'request_id',r.id,
                'record_id',r.record_id,
                'version_id',r.version_id,
                'object_id',r.object_id,
                'storage_path',r.storage_path,
                'ciphertext_sha256',r.ciphertext_sha256,
                'status',r.status,
                'expires_at',r.expires_at,
                'storage_deleted_at',r.storage_deleted_at,
                'metadata_deleted_at',r.metadata_deleted_at,
                'orphaned_at',r.orphaned_at,
                'completed_at',r.completed_at,
                'requested_by',r.requested_by,
                'finalized_by',r.finalized_by,
                'cleanup_attempts',r.cleanup_attempts,
                'last_cleanup_attempt_at',
                    r.last_cleanup_attempt_at,
                'last_cleanup_confirmed_at',
                    r.last_cleanup_confirmed_at,
                'recoverable',(
                    r.status in (
                        'storage_deleted','orphaned','completed'
                    )
                    or not exists (
                        select 1
                        from storage.objects s
                        where s.bucket_id = 'defense-v9-encrypted'
                          and s.name = r.storage_path
                    )
                ),
                'retry_required',(
                    r.status in ('orphaned','completed')
                    and exists (
                        select 1
                        from storage.objects s
                        where s.bucket_id = 'defense-v9-encrypted'
                          and s.name = r.storage_path
                    )
                )
            )
            order by r.created_at,r.id
        ),
        '[]'::jsonb
    ) into result
    from (
        select q.*
        from private.encrypted_object_delete_requests q
        where q.organization_id =
                  list_pending_encrypted_object_deletes.organization_id
          and (
              q.status in (
                  'requested','storage_deleted','orphaned'
              )
              or (
                   q.status = 'completed'
                   and (
                       exists (
                           select 1
                           from storage.objects s
                           where s.bucket_id = 'defense-v9-encrypted'
                             and s.name = q.storage_path
                       )
                       or (
                           q.last_cleanup_attempt_at is not null
                           and (
                               q.last_cleanup_confirmed_at is null
                               or q.last_cleanup_attempt_at >
                                      q.last_cleanup_confirmed_at
                           )
                       )
                   )
              )
          )
        order by q.created_at,q.id
        limit 200
    ) r;
    return result;
end;
$$;

revoke all on function private.can_delete_encrypted_storage_object(text)
    from public, anon, authenticated;
grant execute on function private.can_delete_encrypted_storage_object(text)
    to authenticated;
revoke all on function private.can_insert_encrypted_storage_object(text)
    from public, anon, authenticated;
grant execute on function private.can_insert_encrypted_storage_object(text)
    to authenticated;
revoke all on function private.can_select_encrypted_storage_delete(text)
    from public, anon, authenticated;
grant execute on function private.can_select_encrypted_storage_delete(text)
    to authenticated;
revoke all on function private.guard_encrypted_object_mutation()
    from public, anon, authenticated;
revoke all on function private.guard_workflow_transition()
    from public, anon, authenticated;
revoke all on function public.begin_encrypted_object_delete(uuid,uuid)
    from public, anon, authenticated;
grant execute on function public.begin_encrypted_object_delete(uuid,uuid)
    to authenticated;
revoke all on function public.cancel_encrypted_object_delete(uuid)
    from public, anon, authenticated;
grant execute on function public.cancel_encrypted_object_delete(uuid)
    to authenticated;
revoke all on function public.finalize_encrypted_object_delete(uuid)
    from public, anon, authenticated;
grant execute on function public.finalize_encrypted_object_delete(uuid)
    to authenticated;
revoke all on function
    public.list_pending_encrypted_object_deletes(uuid)
    from public, anon, authenticated;
grant execute on function
    public.list_pending_encrypted_object_deletes(uuid)
    to authenticated;
