-- Close concurrency and privilege gaps in the zero-knowledge RPC surface.
-- Business bodies remain opaque; these functions inspect only identities,
-- versions, roles, key versions, hashes, and ciphertext envelopes.
begin;

-- A snapshot is the one explicit exception to the normal "new record = v1"
-- rule. It lets an existing local ciphertext retain its AAD-bound logical
-- version during the first cloud upload.
alter table public.sync_events
    drop constraint if exists sync_events_operation_check;
alter table public.sync_events
    add constraint sync_events_operation_check check (
        operation in ('upsert','delete','snapshot','rewrap','resolve')
    );

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
    base_id uuid :=
        nullif(p_event->'payload'->>'base_version_id','')::uuid;
    dev_id uuid := (p_event->'payload'->>'device_id')::uuid;
    rec_type text := p_event->'payload'->>'record_type';
    op text := p_event->>'operation';
    logical_ver bigint := (p_event->'payload'->>'version')::bigint;
    submitted_key_version integer :=
        (p_event->'payload'->>'key_version')::integer;
    existing_cursor bigint;
    existing_org uuid;
    organization_key_version integer;
    base_logical_version bigint;
    current_head public.record_heads%rowtype;
    applied boolean := false;
    new_cursor bigint;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    if op not in ('upsert','delete','snapshot') then
        raise exception 'unsupported client operation';
    end if;
    if logical_ver <= 0 then
        raise exception 'logical version must be positive';
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
    if (p_event->'payload'->>'content_hash')
       !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid content hash';
    end if;

    -- An accepted retry stays idempotent even if a key rotation started
    -- after the original transaction.
    select e.cursor,e.organization_id
      into existing_cursor,existing_org
    from public.sync_events e
    where e.event_id = push_record_event.event_id;
    if existing_cursor is not null then
        if existing_org <> org_id then
            raise exception 'event id belongs to another organization';
        end if;
        return jsonb_build_object(
            'cursor',existing_cursor,'duplicate',true,'applied',false
        );
    end if;

    -- FOR SHARE serializes this write with begin/commit rotation, both of
    -- which take FOR UPDATE on the same organization row.
    select o.key_version into organization_key_version
    from public.organizations o
    where o.id = org_id
    for share;
    if not found then
        raise exception 'organization not found';
    end if;
    if exists (
        select 1
        from public.key_rotations r
        where r.organization_id = org_id
          and r.status = 'staging'
    ) then
        raise exception 'key rotation in progress';
    end if;
    if submitted_key_version is null
       or submitted_key_version <> organization_key_version then
        raise exception 'record key version is not current';
    end if;

    select * into current_head
    from public.record_heads h
    where h.organization_id = org_id
      and h.record_id = rec_id
    for update;

    if not found then
        if base_id is not null then
            raise exception 'new record requires null base';
        end if;
        if op = 'snapshot' then
            if logical_ver < 1 then
                raise exception 'snapshot version must be positive';
            end if;
        elsif logical_ver <> 1 then
            raise exception 'new record requires version 1';
        end if;
        insert into public.record_heads(
            organization_id,record_id,record_type,logical_version,deleted
        ) values (org_id,rec_id,rec_type,0,false);
        current_head.organization_id := org_id;
        current_head.record_id := rec_id;
        current_head.record_type := rec_type;
        current_head.logical_version := 0;
        current_head.head_version_id := null;
    else
        if op = 'snapshot' then
            raise exception 'snapshot requires a missing record';
        end if;
        if current_head.record_type <> rec_type then
            raise exception 'record type is immutable';
        end if;
        if base_id is null then
            raise exception 'existing record requires a base version';
        end if;
        select v.logical_version into base_logical_version
        from public.record_versions v
        where v.organization_id = org_id
          and v.record_id = rec_id
          and v.version_id = base_id;
        if not found then
            raise exception 'base version not found';
        end if;
        if base_logical_version + 1 <> logical_ver then
            raise exception 'logical version is not based on base version';
        end if;
    end if;

    insert into public.record_versions(
        organization_id,record_id,version_id,base_version_id,logical_version,
        record_type,device_id,ciphertext,nonce,wrapped_data_key,wrap_nonce,
        key_version,content_hash,deleted
    ) values (
        org_id,rec_id,ver_id,base_id,logical_ver,rec_type,dev_id,
        private.decode_base64url(p_event->'payload'->>'ciphertext'),
        private.decode_base64url(p_event->'payload'->>'nonce'),
        private.decode_base64url(
            p_event->'payload'->>'wrapped_data_key'
        ),
        private.decode_base64url(p_event->'payload'->>'wrap_nonce'),
        submitted_key_version,
        lower(p_event->'payload'->>'content_hash'),
        coalesce(
            (p_event->'payload'->>'deleted')::boolean,
            false
        )
    );

    if (
        current_head.head_version_id is null
        and base_id is null
        and logical_ver >= 1
    ) or (
        current_head.head_version_id = base_id
        and logical_ver = current_head.logical_version + 1
    ) then
        applied := true;
        update public.record_heads h
           set head_version_id = ver_id,
               logical_version = logical_ver,
               deleted = coalesce(
                   (p_event->'payload'->>'deleted')::boolean,
                   false
               ),
               updated_at = now()
         where h.organization_id = org_id
           and h.record_id = rec_id;
    else
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
        'cursor',new_cursor,
        'duplicate',false,
        'applied',applied,
        'conflict',not applied,
        'version_id',ver_id
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
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
    if (select auth.uid()) is null then
        raise exception 'authentication required';
    end if;
    if not exists (
        select 1
        from public.memberships m
        where m.organization_id = pull_sync_events.organization_id
          and m.user_id = (select auth.uid())
          and m.status = 'active'
    ) then
        raise exception 'active membership required';
    end if;

    return query
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
            'wrapped_data_key',
                private.encode_base64url(v.wrapped_data_key),
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
      and e.cursor > greatest(coalesce(after_cursor,0),0)
    order by e.cursor
    limit least(greatest(coalesce(page_size,200),1),500);
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
    locked_organization uuid;
    current_head public.record_heads%rowtype;
    current_state public.workflow_states%rowtype;
    head_content_hash text;
    submitted_hash text := lower(transition_workflow.content_hash);
    previous_hash text;
    next_version bigint;
    calculated_hash text;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;
    if submitted_hash !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid content hash';
    end if;
    -- This organization lock keeps the membership decision, head binding,
    -- and audit-chain append in one serialized organization transaction.
    select o.id into locked_organization
    from public.organizations o
    where o.id = transition_workflow.organization_id
    for update;
    if not found then
        raise exception 'organization not found';
    end if;

    select m.role into actor_role
    from public.memberships m
    where m.organization_id = transition_workflow.organization_id
      and m.user_id = actor
      and m.status = 'active';
    if actor_role is null then
        raise exception 'active membership required';
    end if;

    select h.* into current_head
    from public.record_heads h
    where h.organization_id = transition_workflow.organization_id
      and h.record_id = transition_workflow.record_id
    for update;
    if not found or current_head.head_version_id is null then
        raise exception 'current record head required';
    end if;
    if current_head.record_type not in (
        'document','publication_item'
    ) then
        raise exception 'workflow record type is not publishable';
    end if;

    select v.content_hash into head_content_hash
    from public.record_versions v
    where v.organization_id = transition_workflow.organization_id
      and v.record_id = transition_workflow.record_id
      and v.version_id = current_head.head_version_id;
    if not found then
        raise exception 'current head version not found';
    end if;
    if head_content_hash <> submitted_hash then
        raise exception 'content hash does not match current head';
    end if;

    select * into current_state
    from public.workflow_states w
    where w.organization_id = transition_workflow.organization_id
      and w.record_id = transition_workflow.record_id
    for update;

    if not found then
        if expected_version <> 0
           or target_state not in ('draft','editing') then
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
            submitted_hash,actor
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
        if target_state = 'signed'
           and current_state.state <> 'pending_approval' then
            raise exception 'only pending items can be signed';
        end if;
        if target_state = 'recalled'
           and current_state.state <> 'signed' then
            raise exception 'only signed items can be recalled';
        end if;
        next_version := current_state.version + 1;
        update public.workflow_states
           set state = target_state,
               version = next_version,
               content_hash = submitted_hash,
               updated_by = actor,
               updated_at = now()
         where workflow_states.organization_id =
                   transition_workflow.organization_id
           and workflow_states.record_id =
                   transition_workflow.record_id;
    end if;

    select a.event_hash into previous_hash
    from public.audit_chain a
    where a.organization_id = transition_workflow.organization_id
    order by a.created_at desc,a.id desc
    limit 1;
    calculated_hash := encode(
        extensions.digest(
            coalesce(previous_hash,'')
            || organization_id::text
            || record_id::text
            || target_state
            || next_version::text
            || submitted_hash
            || actor::text,
            'sha256'
        ),
        'hex'
    );
    insert into public.audit_chain(
        organization_id,record_id,event_type,actor_user_id,content_hash,
        previous_hash,event_hash
    ) values (
        organization_id,record_id,'workflow:'||target_state,actor,
        submitted_hash,previous_hash,calculated_hash
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
    current_key_count bigint;
begin
    select o.key_version into current_version
    from public.organizations o
    where o.id = begin_key_rotation.organization_id
    for update;
    if not found then
        raise exception 'organization not found';
    end if;
    if not private.is_org_owner(organization_id) then
        raise exception 'owner required';
    end if;
    if current_version <> expected_key_version then
        raise exception 'expected_key_version mismatch';
    end if;
    if exists (
        select 1
        from public.key_rotations r
        where r.organization_id = begin_key_rotation.organization_id
          and r.status = 'staging'
    ) then
        raise exception 'rotation already in progress';
    end if;

    select
        count(*),
        count(*) filter (where v.key_version = current_version)
      into actual_count,current_key_count
    from public.record_versions v
    where v.organization_id = begin_key_rotation.organization_id;
    if actual_count <> current_key_count then
        raise exception 'record key version set is inconsistent';
    end if;
    if actual_count <> expected_count then
        raise exception 'expected rewrap count mismatch';
    end if;

    insert into public.key_rotations(
        id,organization_id,from_key_version,to_key_version,
        expected_count,created_by
    ) values (
        rotation_id,organization_id,current_version,current_version+1,
        actual_count,(select auth.uid())
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
    rotation_organization uuid;
    rotation public.key_rotations%rowtype;
    entry jsonb;
    entry_record_id uuid;
    entry_version_id uuid;
    total bigint;
begin
    select r.organization_id into rotation_organization
    from public.key_rotations r
    where r.id = stage_rewrap_batch.rotation_id
      and r.status = 'staging';
    if not found then
        raise exception 'active rotation not found';
    end if;

    perform o.id
    from public.organizations o
    where o.id = rotation_organization
    for update;

    select * into rotation
    from public.key_rotations r
    where r.id = stage_rewrap_batch.rotation_id
      and r.status = 'staging'
    for update;
    if not found then
        raise exception 'active rotation not found';
    end if;
    if not private.is_org_owner(rotation.organization_id) then
        raise exception 'owner required';
    end if;
    if jsonb_typeof(entries) <> 'array'
       or jsonb_array_length(entries) > 500 then
        raise exception 'entries must be an array of at most 500';
    end if;

    for entry in
        select value from jsonb_array_elements(entries)
    loop
        entry_record_id := (entry->>'record_id')::uuid;
        entry_version_id := (entry->>'version_id')::uuid;
        perform v.version_id
        from public.record_versions v
        where v.organization_id = rotation.organization_id
          and v.record_id = entry_record_id
          and v.version_id = entry_version_id
          and v.key_version = rotation.from_key_version
        for share;
        if not found then
            raise exception 'rewrap target is not in source key set';
        end if;

        insert into public.key_rotation_entries(
            rotation_id,organization_id,record_id,version_id,
            wrapped_data_key,wrap_nonce
        ) values (
            rotation_id,rotation.organization_id,
            entry_record_id,entry_version_id,
            private.decode_base64url(
                entry->>'wrapped_data_key'
            ),
            private.decode_base64url(entry->>'wrap_nonce')
        )
        on conflict (
            rotation_id,organization_id,record_id,version_id
        )
        do update set
            wrapped_data_key = excluded.wrapped_data_key,
            wrap_nonce = excluded.wrap_nonce;
    end loop;

    select count(*) into total
    from public.key_rotation_entries e
    where e.rotation_id = stage_rewrap_batch.rotation_id;
    if total > rotation.expected_count then
        raise exception 'rewrap target count exceeds rotation set';
    end if;
    update public.key_rotations
       set staged_count = total
     where id = stage_rewrap_batch.rotation_id;
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
    rotation_organization uuid;
    organization_key_version integer;
    rotation public.key_rotations%rowtype;
    actual_count bigint;
    entry_count bigint;
    active_devices bigint;
    new_envelopes bigint;
    updated_count bigint;
    remaining_old_count bigint;
begin
    select r.organization_id into rotation_organization
    from public.key_rotations r
    where r.id = commit_key_rotation.rotation_id
      and r.status = 'staging';
    if not found then
        raise exception 'active rotation not found';
    end if;

    select o.key_version into organization_key_version
    from public.organizations o
    where o.id = rotation_organization
    for update;

    select * into rotation
    from public.key_rotations r
    where r.id = commit_key_rotation.rotation_id
      and r.status = 'staging'
    for update;
    if not found then
        raise exception 'active rotation not found';
    end if;
    if not private.is_org_owner(rotation.organization_id) then
        raise exception 'owner required';
    end if;
    if organization_key_version <> rotation.from_key_version then
        raise exception 'organization key version changed';
    end if;

    -- Lock and recount the exact source-key set. push_record_event cannot
    -- add a record while the rotation is staging, but this is the final
    -- defensive check before the atomic rewrap.
    perform v.version_id
    from public.record_versions v
    where v.organization_id = rotation.organization_id
      and v.key_version = rotation.from_key_version
    for update;
    select count(*) into actual_count
    from public.record_versions v
    where v.organization_id = rotation.organization_id
      and v.key_version = rotation.from_key_version;
    if actual_count <> rotation.expected_count then
        raise exception 'rewrap target set changed';
    end if;

    select count(*) into entry_count
    from public.key_rotation_entries e
    where e.rotation_id = rotation.id;
    update public.key_rotations
       set staged_count = entry_count
     where id = rotation.id;
    if entry_count <> actual_count then
        raise exception 'rewrap batch incomplete';
    end if;
    if exists (
        select 1
        from public.record_versions v
        left join public.key_rotation_entries e
          on e.rotation_id = rotation.id
         and e.organization_id = v.organization_id
         and e.record_id = v.record_id
         and e.version_id = v.version_id
        where v.organization_id = rotation.organization_id
          and v.key_version = rotation.from_key_version
          and e.version_id is null
    ) or exists (
        select 1
        from public.key_rotation_entries e
        left join public.record_versions v
          on v.organization_id = e.organization_id
         and v.record_id = e.record_id
         and v.version_id = e.version_id
         and v.key_version = rotation.from_key_version
        where e.rotation_id = rotation.id
          and v.version_id is null
    ) then
        raise exception 'rewrap target set changed';
    end if;

    select count(*) into active_devices
    from public.devices d
    where d.organization_id = rotation.organization_id
      and d.status = 'active';
    select count(*) into new_envelopes
    from public.key_envelopes e
    where e.organization_id = rotation.organization_id
      and e.key_version = rotation.to_key_version;
    if new_envelopes <> active_devices then
        raise exception 'device envelope set incomplete';
    end if;
    if not exists (
        select 1
        from public.recovery_envelopes r
        where r.organization_id = rotation.organization_id
          and r.key_version = rotation.to_key_version
    ) then
        raise exception 'new recovery envelope required';
    end if;

    update public.record_versions v
       set wrapped_data_key = e.wrapped_data_key,
           wrap_nonce = e.wrap_nonce,
           key_version = rotation.to_key_version
      from public.key_rotation_entries e
     where e.rotation_id = rotation.id
       and v.organization_id = e.organization_id
       and v.record_id = e.record_id
       and v.version_id = e.version_id
       and v.key_version = rotation.from_key_version;
    get diagnostics updated_count = row_count;
    if updated_count <> actual_count then
        raise exception 'rewrap update count mismatch';
    end if;
    select count(*) into remaining_old_count
    from public.record_versions v
    where v.organization_id = rotation.organization_id
      and v.key_version = rotation.from_key_version;
    if remaining_old_count <> 0 then
        raise exception 'source key versions remain';
    end if;

    update public.organizations
       set key_version = rotation.to_key_version,
           updated_at = now()
     where id = rotation.organization_id
       and key_version = rotation.from_key_version;
    if not found then
        raise exception 'organization key version changed';
    end if;
    update public.key_rotations
       set status = 'committed',
           staged_count = actual_count,
           committed_at = now()
     where id = rotation.id;
    return rotation.to_key_version;
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
    locked_organization uuid;
    target_role text;
    owner_count bigint;
begin
    -- One row lock serializes every revocation in an organization. Two
    -- concurrent owners therefore cannot both observe owner_count = 2.
    select o.id into locked_organization
    from public.organizations o
    where o.id = revoke_member.organization_id
    for update;
    if not found then
        raise exception 'organization not found';
    end if;
    if not private.is_org_admin(organization_id) then
        raise exception 'owner or admin required';
    end if;

    select m.role into target_role
    from public.memberships m
    where m.organization_id = revoke_member.organization_id
      and m.user_id = target_user_id
      and m.status = 'active'
    for update;
    if target_role is null then
        return false;
    end if;
    if target_role = 'owner' then
        if not private.is_org_owner(organization_id) then
            raise exception 'admin cannot revoke owner';
        end if;
        select count(*) into owner_count
        from public.memberships m
        where m.organization_id = revoke_member.organization_id
          and m.role = 'owner'
          and m.status = 'active';
        if owner_count <= 1 then
            raise exception 'cannot revoke the last owner';
        end if;
    end if;

    update public.memberships
       set status = 'revoked',
           revoked_at = now()
     where memberships.organization_id =
               revoke_member.organization_id
       and memberships.user_id = target_user_id;
    update public.devices
       set status = 'revoked',
           revoked_at = now()
     where devices.organization_id =
               revoke_member.organization_id
       and devices.user_id = target_user_id
       and devices.status <> 'revoked';
    return true;
end;
$$;

-- Private codecs remain implementation details. The public pull RPC runs as
-- definer only after its own active-membership check.
revoke all on function private.encode_base64url(bytea)
    from public, anon, authenticated;

revoke all on function public.push_record_event(jsonb)
    from public, anon, authenticated;
revoke all on function public.pull_sync_events(uuid,bigint,integer)
    from public, anon, authenticated;
revoke all on function public.transition_workflow(
    uuid,uuid,bigint,text,text
) from public, anon, authenticated;
revoke all on function public.begin_key_rotation(uuid,integer,bigint)
    from public, anon, authenticated;
revoke all on function public.stage_rewrap_batch(uuid,jsonb)
    from public, anon, authenticated;
revoke all on function public.commit_key_rotation(uuid)
    from public, anon, authenticated;
revoke all on function public.revoke_member(uuid,uuid)
    from public, anon, authenticated;

grant execute on function public.push_record_event(jsonb)
    to authenticated;
grant execute on function public.pull_sync_events(uuid,bigint,integer)
    to authenticated;
grant execute on function public.transition_workflow(
    uuid,uuid,bigint,text,text
) to authenticated;
grant execute on function public.begin_key_rotation(uuid,integer,bigint)
    to authenticated;
grant execute on function public.stage_rewrap_batch(uuid,jsonb)
    to authenticated;
grant execute on function public.commit_key_rotation(uuid)
    to authenticated;
grant execute on function public.revoke_member(uuid,uuid)
    to authenticated;

commit;
