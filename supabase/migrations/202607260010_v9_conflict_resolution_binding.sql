-- Bind conflict resolution to the exact tenant, record, event, and version.
-- The encrypted record body remains opaque; only identity/version metadata is
-- inspected.
begin;

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
    actor uuid := (select auth.uid());
    target public.conflicts%rowtype;
    target_record_type text;
    current_head_version_id uuid;
    payload jsonb;
    resolution_event_id uuid;
    retry_version_id uuid;
    retry_base_version_id uuid;
    retry_device_id uuid;
    retry_operation text;
    retry_logical_version bigint;
    retry_key_version integer;
    retry_deleted boolean;
    canonical_request jsonb;
    incoming_request_hash text;
    resolved_cursor bigint;
    resolved_version_id uuid;
    pushed jsonb;
begin
    if actor is null then
        raise exception 'authentication required';
    end if;

    select * into target
    from public.conflicts c
    where c.id = resolve_conflict.conflict_id
    for update;
    if not found then
        raise exception 'conflict not found';
    end if;

    select h.record_type,h.head_version_id
      into target_record_type,current_head_version_id
    from public.record_heads h
    where h.organization_id = target.organization_id
      and h.record_id = target.record_id
    for update;
    if not found then
        raise exception 'conflict record not found';
    end if;

    -- can_write_record requires an active membership and applies the
    -- six-role record-type permission matrix.
    if not private.can_write_record(
        target.organization_id,target_record_type
    ) then
        raise exception 'record write denied';
    end if;

    if resolution_event is null
       or jsonb_typeof(resolution_event) <> 'object' then
        raise exception 'resolution event must be an object';
    end if;
    if not (
        resolution_event ?& array[
            'event_id','organization_id','record_id','operation','payload'
        ]::text[]
    ) then
        raise exception 'missing resolution event field';
    end if;
    if exists (
        select 1
        from jsonb_object_keys(resolution_event) as event_key(key_name)
        where key_name not in (
            'event_id','organization_id','record_id','operation','payload'
        )
    ) then
        raise exception 'unsupported resolution event field';
    end if;

    payload := resolution_event->'payload';
    if jsonb_typeof(payload) <> 'object' then
        raise exception 'resolution payload must be an object';
    end if;
    if not (
        payload ?& array[
            'organization_id','record_id','record_type','version',
            'version_id','base_version_id','key_version','ciphertext',
            'nonce','wrapped_data_key','wrap_nonce','content_hash',
            'device_id','deleted'
        ]::text[]
    ) then
        raise exception 'missing resolution payload field';
    end if;
    if exists (
        select 1
        from jsonb_object_keys(payload) as payload_key(key_name)
        where key_name not in (
            'organization_id','record_id','record_type','version',
            'version_id','base_version_id','key_version','ciphertext',
            'nonce','wrapped_data_key','wrap_nonce','content_hash',
            'device_id','deleted','updated_at'
        )
    ) then
        raise exception 'unsupported resolution payload field';
    end if;

    resolution_event_id :=
        nullif(resolution_event->>'event_id','')::uuid;
    if resolution_event_id is null
       or resolution_event->>'organization_id'
          is distinct from target.organization_id::text
       or resolution_event->>'record_id'
          is distinct from target.record_id::text
       or resolution_event->'payload'->>'organization_id'
          is distinct from target.organization_id::text
       or resolution_event->'payload'->>'record_id'
          is distinct from target.record_id::text then
        raise exception 'resolution event identity mismatch';
    end if;

    -- A committed response may be lost after the database transaction
    -- completes.  Retry only the exact event/version already recorded for
    -- this conflict; do not call push_record_event a second time.
    if target.status = 'resolved' then
        retry_version_id :=
            nullif(payload->>'version_id','')::uuid;
        if target.resolution_version_id is null
           or retry_version_id
              is distinct from target.resolution_version_id then
            raise exception 'resolved conflict retry mismatch';
        end if;

        retry_base_version_id :=
            nullif(payload->>'base_version_id','')::uuid;
        retry_device_id := (payload->>'device_id')::uuid;
        retry_operation := resolution_event->>'operation';
        retry_logical_version := (payload->>'version')::bigint;
        retry_key_version := (payload->>'key_version')::integer;
        retry_deleted := coalesce(
            (payload->>'deleted')::boolean,
            false
        );
        canonical_request := jsonb_build_object(
            'event_id',resolution_event_id,
            'organization_id',target.organization_id,
            'record_id',target.record_id,
            'operation',retry_operation,
            'payload',jsonb_build_object(
                'organization_id',target.organization_id,
                'record_id',target.record_id,
                'version_id',retry_version_id,
                'base_version_id',retry_base_version_id,
                'device_id',retry_device_id,
                'record_type',payload->>'record_type',
                'version',retry_logical_version,
                'key_version',retry_key_version,
                'ciphertext',payload->>'ciphertext',
                'nonce',payload->>'nonce',
                'wrapped_data_key',payload->>'wrapped_data_key',
                'wrap_nonce',payload->>'wrap_nonce',
                'content_hash',lower(payload->>'content_hash'),
                'deleted',retry_deleted
            )
        );
        incoming_request_hash := encode(
            extensions.digest(
                convert_to(canonical_request::text,'UTF8'),
                'sha256'
            ),
            'hex'
        );

        select e.cursor,e.version_id
          into resolved_cursor,resolved_version_id
        from public.sync_events e
        join public.record_versions v
          on v.organization_id = e.organization_id
         and v.record_id = e.record_id
         and v.version_id = e.version_id
        where e.event_id = resolution_event_id
          and e.organization_id = target.organization_id
          and e.record_id = target.record_id
          and e.applied = true
          and e.version_id = target.resolution_version_id
          and e.request_hash = incoming_request_hash
          and v.organization_id = target.organization_id
          and v.record_id = target.record_id;
        if not found then
            raise exception 'resolved conflict retry mismatch';
        end if;
        if current_head_version_id
           is distinct from target.resolution_version_id then
            raise exception 'resolved conflict head changed';
        end if;

        return jsonb_build_object(
            'cursor',resolved_cursor,
            'applied',true,
            'duplicate',true,
            'conflict',false,
            'version_id',target.resolution_version_id,
            'head_version_id',target.resolution_version_id,
            'resolved_conflict_id',resolve_conflict.conflict_id
        );
    end if;
    if target.status <> 'open' then
        raise exception 'unsupported conflict status';
    end if;
    if current_head_version_id is distinct from expected_head_version_id then
        raise exception 'head changed during resolution';
    end if;

    pushed := public.push_record_event(resolution_event);
    if not coalesce((pushed->>'applied')::boolean,false) then
        raise exception 'resolution created another conflict';
    end if;

    select e.version_id into resolved_version_id
    from public.sync_events e
    join public.record_versions v
      on v.organization_id = e.organization_id
     and v.record_id = e.record_id
     and v.version_id = e.version_id
    where e.event_id = resolution_event_id
      and e.organization_id = target.organization_id
      and e.record_id = target.record_id
      and e.applied = true
      and e.version_id = (pushed->>'version_id')::uuid
      and v.organization_id = target.organization_id
      and v.record_id = target.record_id;
    if not found then
        raise exception 'resolution event binding mismatch';
    end if;

    if (
        select h.head_version_id
        from public.record_heads h
        where h.organization_id = target.organization_id
          and h.record_id = target.record_id
    ) is distinct from resolved_version_id then
        raise exception 'resolution event is not current target version';
    end if;

    update public.conflicts
       set status='resolved',
           resolved_at=now(),
           resolved_by=actor,
           resolution_version_id=resolved_version_id
     where id=resolve_conflict.conflict_id
       and organization_id=target.organization_id
       and record_id=target.record_id
       and status='open';

    return pushed || jsonb_build_object(
        'resolved_conflict_id',resolve_conflict.conflict_id
    );
end;
$$;

-- The legacy private implementation is no longer part of the call path.
revoke all on function private.resolve_conflict(uuid,uuid,jsonb)
    from public, anon, authenticated;
revoke all on function public.resolve_conflict(uuid,uuid,jsonb)
    from public, anon, authenticated;
grant execute on function public.resolve_conflict(uuid,uuid,jsonb)
    to authenticated;

commit;
