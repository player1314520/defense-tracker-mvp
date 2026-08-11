-- Bind publishable workflow states to their current ciphertext object set and
-- require a short-lived, user-bound ticket for physical object deletion.
-- Business plaintext and decryption material never enter these structures.

alter table public.workflow_states
    add column if not exists bound_version_id uuid,
    add column if not exists object_manifest_hash text,
    add column if not exists object_count bigint;

alter table public.workflow_states
    drop constraint if exists workflow_states_bound_version_fk,
    add constraint workflow_states_bound_version_fk
        foreign key (organization_id,record_id,bound_version_id)
        references public.record_versions(
            organization_id,record_id,version_id
        ),
    drop constraint if exists workflow_states_object_manifest_check,
    add constraint workflow_states_object_manifest_check check (
        (
            state in ('pending_approval','signed','recalled')
            and bound_version_id is not null
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

create table private.encrypted_object_delete_requests (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null
        references public.organizations(id) on delete cascade,
    record_id uuid not null,
    version_id uuid not null,
    object_id uuid not null,
    storage_path text not null,
    ciphertext_sha256 text not null
        check (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
    requested_by uuid not null references auth.users(id),
    status text not null default 'requested'
        check (status in ('requested','completed','cancelled')),
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    completed_at timestamptz,
    foreign key (organization_id,record_id,version_id)
        references public.record_versions(
            organization_id,record_id,version_id
        ),
    check (expires_at > created_at)
);

create index encrypted_object_delete_requests_lookup_idx
    on private.encrypted_object_delete_requests(
        organization_id,object_id,requested_by,status,expires_at
    );

revoke all on table private.encrypted_object_delete_requests
    from public, anon, authenticated;

create or replace function private.current_object_manifest(
    target_organization_id uuid,
    target_record_id uuid,
    target_version_id uuid
)
returns table(
    object_count bigint,
    object_manifest_hash text,
    physical_count bigint
)
language sql
stable
security definer
set search_path = ''
as $$
    select
        count(o.id)::bigint,
        encode(
            extensions.digest(
                convert_to(
                    coalesce(
                        string_agg(
                            o.id::text || ':' ||
                            o.storage_path || ':' ||
                            o.ciphertext_sha256 || ':' ||
                            o.byte_length::text,
                            E'\n'
                            order by
                                o.id::text,
                                o.storage_path,
                                o.ciphertext_sha256,
                                o.byte_length
                        ),
                        ''
                    ),
                    'UTF8'
                ),
                'sha256'
            ),
            'hex'
        ),
        count(s.id)::bigint
    from public.encrypted_objects o
    left join storage.objects s
      on s.bucket_id = 'defense-v9-encrypted'
     and s.name = o.storage_path
    where o.organization_id =
              current_object_manifest.target_organization_id
      and o.record_id = current_object_manifest.target_record_id
      and o.version_id = current_object_manifest.target_version_id;
$$;

create or replace function private.append_object_audit(
    target_organization_id uuid,
    target_record_id uuid,
    target_event_type text,
    target_actor uuid,
    target_content_hash text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
    previous_hash text;
    calculated_hash text;
begin
    if target_actor is null then
        raise exception 'authentication required';
    end if;
    if target_content_hash !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid audit content hash';
    end if;
    perform 1
    from public.organizations o
    where o.id = append_object_audit.target_organization_id
    for update;
    if not found then
        raise exception 'organization not found';
    end if;
    select a.event_hash into previous_hash
    from public.audit_chain a
    where a.organization_id =
              append_object_audit.target_organization_id
    order by a.created_at desc,a.id desc
    limit 1;
    calculated_hash := encode(
        extensions.digest(
            coalesce(previous_hash,'')
            || target_organization_id::text
            || target_record_id::text
            || target_event_type
            || lower(target_content_hash)
            || target_actor::text,
            'sha256'
        ),
        'hex'
    );
    insert into public.audit_chain(
        organization_id,record_id,event_type,actor_user_id,content_hash,
        previous_hash,event_hash
    ) values (
        target_organization_id,target_record_id,target_event_type,
        target_actor,lower(target_content_hash),previous_hash,calculated_hash
    );
end;
$$;

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
    if not found or head_content_hash <> new.content_hash then
        raise exception 'workflow content hash does not match current head';
    end if;
    select * into manifest
    from private.current_object_manifest(
        new.organization_id,new.record_id,current_head.head_version_id
    );
    if manifest.physical_count <> manifest.object_count then
        raise exception 'workflow object metadata/storage mismatch';
    end if;

    if new.state = 'pending_approval' then
        new.bound_version_id := current_head.head_version_id;
        new.object_manifest_hash := manifest.object_manifest_hash;
        new.object_count := manifest.object_count;
        return new;
    end if;

    if new.state = 'signed' then
        if old.content_hash <> new.content_hash then
            raise exception 'pending approval content hash changed';
        end if;
        if old.bound_version_id <> current_head.head_version_id
           or old.object_count <> manifest.object_count
           or old.object_manifest_hash <> manifest.object_manifest_hash then
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
    target_request private.encrypted_object_delete_requests%rowtype;
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
            from public.workflow_states w
            where w.organization_id = new.organization_id
              and w.record_id = new.record_id
              and w.bound_version_id = new.version_id
              and w.state in ('pending_approval','signed')
        ) then
            raise exception 'protected workflow objects are immutable';
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
          and w.state in ('pending_approval','signed')
    ) then
        raise exception 'protected workflow objects cannot be deleted';
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
    select r.* into target_request
    from private.encrypted_object_delete_requests r
    where r.id = request_id
      and r.organization_id = old.organization_id
      and r.record_id = old.record_id
      and r.version_id = old.version_id
      and r.object_id = old.id
      and r.storage_path = old.storage_path
      and r.ciphertext_sha256 = old.ciphertext_sha256
      and r.requested_by = (select auth.uid())
      and r.status = 'requested'
      and r.expires_at > now()
    for share;
    if not found then
        raise exception 'valid object delete ticket required';
    end if;
    if exists (
        select 1
        from storage.objects s
        where s.bucket_id = 'defense-v9-encrypted'
          and s.name = old.storage_path
    ) then
        raise exception 'storage object must be deleted before metadata finalize';
    end if;
    return old;
end;
$$;

drop trigger if exists guard_encrypted_object_mutation
    on public.encrypted_objects;
create trigger guard_encrypted_object_mutation
before insert or update or delete on public.encrypted_objects
for each row execute function private.guard_encrypted_object_mutation();

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
    if current_state.state in ('pending_approval','signed')
       and current_state.bound_version_id = target_object.version_id then
        raise exception 'protected workflow objects cannot be deleted';
    end if;
    if not exists (
        select 1
        from storage.objects s
        where s.bucket_id = 'defense-v9-encrypted'
          and s.name = target_object.storage_path
    ) then
        raise exception 'storage object not found';
    end if;

    update private.encrypted_object_delete_requests r
       set status = 'cancelled'
     where r.organization_id = target_object.organization_id
       and r.object_id = target_object.id
       and r.requested_by = actor
       and r.status = 'requested';
    insert into private.encrypted_object_delete_requests(
        organization_id,record_id,version_id,object_id,storage_path,
        ciphertext_sha256,requested_by,expires_at
    ) values (
        target_object.organization_id,target_object.record_id,
        target_object.version_id,target_object.id,
        target_object.storage_path,target_object.ciphertext_sha256,
        actor,now() + interval '5 minutes'
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

create or replace function private.can_delete_encrypted_storage_object(
    object_path text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
    actor uuid := (select auth.uid());
    path_organization_id uuid;
    target_object public.encrypted_objects%rowtype;
    actor_role text;
    current_state public.workflow_states%rowtype;
begin
    if actor is null then
        return false;
    end if;
    path_organization_id := private.path_org_uuid(object_path);
    if path_organization_id is null then
        return false;
    end if;
    perform 1
    from public.organizations org
    where org.id = path_organization_id
    for share;
    if not found then
        return false;
    end if;
    select o.* into target_object
    from public.encrypted_objects o
    where o.organization_id = path_organization_id
      and o.storage_path = object_path;
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
    select w.* into current_state
    from public.workflow_states w
    where w.organization_id = target_object.organization_id
      and w.record_id = target_object.record_id
    for share;
    if current_state.state in ('pending_approval','signed')
       and current_state.bound_version_id = target_object.version_id then
        return false;
    end if;
    return exists (
        select 1
        from private.encrypted_object_delete_requests r
        where r.organization_id = target_object.organization_id
          and r.record_id = target_object.record_id
          and r.version_id = target_object.version_id
          and r.object_id = target_object.id
          and r.storage_path = target_object.storage_path
          and r.ciphertext_sha256 = target_object.ciphertext_sha256
          and r.requested_by = actor
          and r.status = 'requested'
          and r.expires_at > now()
    );
end;
$$;

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
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    select r.* into request_snapshot
    from private.encrypted_object_delete_requests r
    where r.id = finalize_encrypted_object_delete.request_id;
    if not found then
        raise exception 'object delete request not found';
    end if;
    perform 1
    from public.organizations org
    where org.id = request_snapshot.organization_id
    for update;
    if not found then
        raise exception 'organization not found';
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
    select o.* into target_object
    from public.encrypted_objects o
    where o.organization_id = request_snapshot.organization_id
      and o.record_id = request_snapshot.record_id
      and o.version_id = request_snapshot.version_id
      and o.id = request_snapshot.object_id
    for update;
    if not found then
        raise exception 'encrypted object not found';
    end if;
    select r.* into target_request
    from private.encrypted_object_delete_requests r
    where r.id = finalize_encrypted_object_delete.request_id
      and r.organization_id = target_object.organization_id
      and r.record_id = target_object.record_id
      and r.version_id = target_object.version_id
      and r.object_id = target_object.id
      and r.storage_path = target_object.storage_path
      and r.ciphertext_sha256 = target_object.ciphertext_sha256
      and r.requested_by = actor
    for update;
    if not found
       or target_request.status <> 'requested'
       or target_request.expires_at <= now() then
        raise exception 'valid object delete ticket required';
    end if;
    if current_state.state in ('pending_approval','signed')
       and current_state.bound_version_id = target_object.version_id then
        raise exception 'protected workflow objects cannot be deleted';
    end if;
    if exists (
        select 1
        from storage.objects s
        where s.bucket_id = 'defense-v9-encrypted'
          and s.name = target_object.storage_path
    ) then
        raise exception 'storage object must be deleted before metadata finalize';
    end if;
    perform set_config(
        'defense_tracker.object_delete_request',
        target_request.id::text,
        true
    );
    delete from public.encrypted_objects o
    where o.organization_id = target_object.organization_id
      and o.id = target_object.id;
    update private.encrypted_object_delete_requests r
       set status = 'completed',completed_at = now()
     where r.id = target_request.id;
    perform private.append_object_audit(
        target_object.organization_id,
        target_object.record_id,
        'object_deleted:' || target_request.id::text,
        actor,
        target_object.ciphertext_sha256
    );
    return jsonb_build_object(
        'request_id',target_request.id,
        'organization_id',target_object.organization_id,
        'record_id',target_object.record_id,
        'version_id',target_object.version_id,
        'object_id',target_object.id,
        'storage_path',target_object.storage_path,
        'ciphertext_sha256',target_object.ciphertext_sha256,
        'status','completed'
    );
end;
$$;

revoke delete on public.encrypted_objects from authenticated;
drop policy if exists encrypted_objects_delete
    on public.encrypted_objects;
drop policy if exists v9_storage_delete
    on storage.objects;
create policy v9_storage_delete on storage.objects
for delete to authenticated using (
    bucket_id = 'defense-v9-encrypted'
    and private.can_delete_encrypted_storage_object(name)
);

revoke all on function private.current_object_manifest(uuid,uuid,uuid)
    from public, anon, authenticated;
revoke all on function private.append_object_audit(
    uuid,uuid,text,uuid,text
) from public, anon, authenticated;
revoke all on function private.guard_workflow_transition()
    from public, anon, authenticated;
revoke all on function private.guard_encrypted_object_mutation()
    from public, anon, authenticated;
revoke all on function private.can_delete_encrypted_storage_object(text)
    from public, anon, authenticated;
grant execute on function private.can_delete_encrypted_storage_object(text)
    to authenticated;
revoke all on function public.begin_encrypted_object_delete(uuid,uuid)
    from public, anon, authenticated;
revoke all on function public.finalize_encrypted_object_delete(uuid)
    from public, anon, authenticated;
grant execute on function public.begin_encrypted_object_delete(uuid,uuid)
    to authenticated;
grant execute on function public.finalize_encrypted_object_delete(uuid)
    to authenticated;
