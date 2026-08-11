-- Bound encrypted record rows to the client AES-GCM envelope contract.
-- A 16 MiB canonical JSON body plus its 16-byte GCM tag remains below the
-- 24 MiB encoded sync-event budget while preserving the existing app limit.
begin;

alter table public.record_versions
    drop constraint if exists record_versions_ciphertext_size_check;
alter table public.record_versions
    add constraint record_versions_ciphertext_size_check check (
        octet_length(ciphertext) between 17 and 16777232
    );

alter table public.record_versions
    drop constraint if exists record_versions_nonce_size_check;
alter table public.record_versions
    add constraint record_versions_nonce_size_check check (
        octet_length(nonce) = 12
    );

alter table public.record_versions
    drop constraint if exists record_versions_wrapped_key_size_check;
alter table public.record_versions
    add constraint record_versions_wrapped_key_size_check check (
        octet_length(wrapped_data_key) = 48
    );

alter table public.record_versions
    drop constraint if exists record_versions_wrap_nonce_size_check;
alter table public.record_versions
    add constraint record_versions_wrap_nonce_size_check check (
        octet_length(wrap_nonce) = 12
    );

create or replace function private.validate_sync_ciphertext_event(
    p_event jsonb
)
returns void
language plpgsql
immutable
security invoker
set search_path = ''
as $$
declare
    payload jsonb;
    uuid_pattern constant text :=
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
    field_name text;
    encoded_value text;
    decoded_ciphertext bytea;
    decoded_nonce bytea;
    decoded_wrapped_data_key bytea;
    decoded_wrap_nonce bytea;
begin
    if p_event is null
       or jsonb_typeof(p_event) <> 'object' then
        raise exception 'encrypted event must be an object';
    end if;
    if octet_length(convert_to(p_event::text,'UTF8')) > 25165824 then
        raise exception 'encrypted event exceeds sync size limit';
    end if;
    if not (
        p_event ?& array[
            'event_id','organization_id','record_id','operation','payload'
        ]::text[]
    ) then
        raise exception 'missing event field';
    end if;
    if exists (
        select 1
        from jsonb_object_keys(p_event) as event_key(key_name)
        where key_name not in (
            'event_id','organization_id','record_id','operation','payload'
        )
    ) then
        raise exception 'unsupported event field';
    end if;
    if jsonb_typeof(p_event->'event_id') <> 'string'
       or jsonb_typeof(p_event->'organization_id') <> 'string'
       or jsonb_typeof(p_event->'record_id') <> 'string'
       or jsonb_typeof(p_event->'operation') <> 'string'
       or jsonb_typeof(p_event->'payload') <> 'object' then
        raise exception 'invalid event field type';
    end if;

    payload := p_event->'payload';
    if jsonb_typeof(payload) <> 'object' then
        raise exception 'encrypted payload must be an object';
    end if;
    if not (
        payload ?& array[
            'organization_id','record_id','record_type','version',
            'version_id','base_version_id','key_version','ciphertext',
            'nonce','wrapped_data_key','wrap_nonce','content_hash',
            'device_id','deleted'
        ]::text[]
    ) then
        raise exception 'missing payload field';
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
        raise exception 'unsupported payload field';
    end if;
    if jsonb_typeof(payload->'organization_id') <> 'string'
       or jsonb_typeof(payload->'record_id') <> 'string'
       or jsonb_typeof(payload->'record_type') <> 'string'
       or jsonb_typeof(payload->'version') <> 'number'
       or jsonb_typeof(payload->'version_id') <> 'string'
       or jsonb_typeof(payload->'key_version') <> 'number'
       or jsonb_typeof(payload->'ciphertext') <> 'string'
       or jsonb_typeof(payload->'nonce') <> 'string'
       or jsonb_typeof(payload->'wrapped_data_key') <> 'string'
       or jsonb_typeof(payload->'wrap_nonce') <> 'string'
       or jsonb_typeof(payload->'content_hash') <> 'string'
       or jsonb_typeof(payload->'device_id') <> 'string'
       or jsonb_typeof(payload->'deleted') <> 'boolean'
       or not (
           jsonb_typeof(payload->'base_version_id') = 'null'
           or jsonb_typeof(payload->'base_version_id') = 'string'
       ) then
        raise exception 'invalid payload field type';
    end if;
    if payload ? 'updated_at'
       and (
           jsonb_typeof(payload->'updated_at') <> 'string'
           or octet_length(payload->>'updated_at') > 64
       ) then
        raise exception 'invalid updated_at';
    end if;

    if (p_event->>'event_id') !~ uuid_pattern
       or (p_event->>'organization_id') !~ uuid_pattern
       or (p_event->>'record_id') !~ uuid_pattern
       or (payload->>'organization_id') !~ uuid_pattern
       or (payload->>'record_id') !~ uuid_pattern
       or (payload->>'version_id') !~ uuid_pattern
       or (payload->>'device_id') !~ uuid_pattern
       or (
           jsonb_typeof(payload->'base_version_id') = 'string'
           and (payload->>'base_version_id') !~ uuid_pattern
       ) then
        raise exception 'uuid fields must be canonical';
    end if;
    if payload->>'organization_id'
       is distinct from p_event->>'organization_id'
       or payload->>'record_id'
          is distinct from p_event->>'record_id' then
        raise exception 'payload identity mismatch';
    end if;
    if p_event->>'operation' not in ('upsert','delete','snapshot') then
        raise exception 'unsupported client operation';
    end if;
    if (
        p_event->>'operation' = 'delete'
        and payload->>'deleted' <> 'true'
    ) or (
        p_event->>'operation' = 'upsert'
        and payload->>'deleted' <> 'false'
    ) then
        raise exception 'operation and deleted state mismatch';
    end if;
    if payload->>'record_type' not in (
        'source','evidence','claim','entity','relation','geo_event',
        'alert_rule','alert','case','job','scenario','document',
        'publication_item','audit_event'
    ) then
        raise exception 'unsupported record type';
    end if;

    if (payload->>'version') !~ '^[1-9][0-9]{0,18}$' then
        raise exception 'logical version must be a positive integer';
    end if;
    if (payload->>'version')::numeric > 9223372036854775807 then
        raise exception 'logical version exceeds bigint range';
    end if;
    if (payload->>'key_version') !~ '^[1-9][0-9]{0,9}$' then
        raise exception 'key version must be a positive integer';
    end if;
    if (payload->>'key_version')::numeric > 2147483647 then
        raise exception 'key version exceeds integer range';
    end if;
    if (payload->>'content_hash') !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid content hash';
    end if;

    foreach field_name in array array[
        'ciphertext','nonce','wrapped_data_key','wrap_nonce'
    ] loop
        encoded_value := payload->>field_name;
        if encoded_value !~ '^[A-Za-z0-9_-]+$'
           or length(encoded_value) % 4 = 1 then
            raise exception '% must be canonical unpadded base64url',
                field_name;
        end if;
    end loop;

    decoded_ciphertext :=
        private.decode_base64url(payload->>'ciphertext');
    decoded_nonce :=
        private.decode_base64url(payload->>'nonce');
    decoded_wrapped_data_key :=
        private.decode_base64url(payload->>'wrapped_data_key');
    decoded_wrap_nonce :=
        private.decode_base64url(payload->>'wrap_nonce');

    if private.encode_base64url(decoded_ciphertext)
           <> payload->>'ciphertext'
       or private.encode_base64url(decoded_nonce)
           <> payload->>'nonce'
       or private.encode_base64url(decoded_wrapped_data_key)
           <> payload->>'wrapped_data_key'
       or private.encode_base64url(decoded_wrap_nonce)
           <> payload->>'wrap_nonce' then
        raise exception 'ciphertext fields must be canonical base64url';
    end if;
    if not (
        octet_length(decoded_ciphertext) between 17 and 16777232
    ) then
        raise exception 'ciphertext has invalid encrypted length';
    end if;
    if not (octet_length(decoded_nonce) = 12) then
        raise exception 'nonce has invalid encrypted length';
    end if;
    if not (octet_length(decoded_wrapped_data_key) = 48) then
        raise exception 'wrapped_data_key has invalid encrypted length';
    end if;
    if not (octet_length(decoded_wrap_nonce) = 12) then
        raise exception 'wrap_nonce has invalid encrypted length';
    end if;
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
    payload jsonb;
    event_id uuid;
    org_id uuid;
    rec_id uuid;
    ver_id uuid;
    base_id uuid;
    dev_id uuid;
    rec_type text;
    op text;
    logical_ver bigint;
    submitted_key_version integer;
    submitted_deleted boolean;
    existing_cursor bigint;
    existing_org uuid;
    existing_applied boolean;
    existing_version_id uuid;
    existing_request_hash text;
    canonical_request jsonb;
    incoming_request_hash text;
    organization_key_version integer;
    base_logical_version bigint;
    current_head public.record_heads%rowtype;
    current_head_id uuid;
    applied boolean := false;
    new_cursor bigint;
begin
    perform private.validate_sync_ciphertext_event(p_event);

    if actor is null then
        raise exception 'authentication required';
    end if;

    if p_event is null
       or jsonb_typeof(p_event) <> 'object' then
        raise exception 'encrypted event must be an object';
    end if;
    if not (
        p_event ?& array[
            'event_id','organization_id','record_id','operation','payload'
        ]::text[]
    ) then
        raise exception 'missing event field';
    end if;
    if exists (
        select 1
        from jsonb_object_keys(p_event) as event_key(key_name)
        where key_name not in (
            'event_id','organization_id','record_id','operation','payload'
        )
    ) then
        raise exception 'unsupported event field';
    end if;

    payload := p_event->'payload';
    if jsonb_typeof(payload) <> 'object' then
        raise exception 'encrypted payload must be an object';
    end if;
    if not (
        payload ?& array[
            'organization_id','record_id','record_type','version',
            'version_id','base_version_id','key_version','ciphertext',
            'nonce','wrapped_data_key','wrap_nonce','content_hash',
            'device_id','deleted'
        ]::text[]
    ) then
        raise exception 'missing payload field';
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
        raise exception 'unsupported payload field';
    end if;

    event_id := (p_event->>'event_id')::uuid;
    org_id := (p_event->>'organization_id')::uuid;
    rec_id := (p_event->>'record_id')::uuid;
    ver_id := (payload->>'version_id')::uuid;
    base_id := nullif(payload->>'base_version_id','')::uuid;
    dev_id := (payload->>'device_id')::uuid;
    rec_type := payload->>'record_type';
    op := p_event->>'operation';
    logical_ver := (payload->>'version')::bigint;
    submitted_key_version := (payload->>'key_version')::integer;
    submitted_deleted := coalesce(
        (payload->>'deleted')::boolean,
        false
    );

    if op not in ('upsert','delete','snapshot') then
        raise exception 'unsupported client operation';
    end if;
    if logical_ver <= 0 then
        raise exception 'logical version must be positive';
    end if;
    if payload->>'organization_id' <> org_id::text
       or payload->>'record_id' <> rec_id::text then
        raise exception 'payload identity mismatch';
    end if;
    if not private.can_write_record(org_id,rec_type) then
        raise exception 'record write denied';
    end if;
    if op = 'snapshot'
       and not private.is_org_owner(org_id) then
        raise exception 'snapshot requires owner';
    end if;
    if not private.is_active_device_owner(org_id,dev_id) then
        raise exception 'active caller device required';
    end if;
    if (payload->>'content_hash')
       !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid content hash';
    end if;

    -- Serialize all attempts for this event ID before checking the event log,
    -- including concurrent first submissions.
    perform pg_advisory_xact_lock(
        hashtextextended(event_id::text,0)
    );

    canonical_request := jsonb_build_object(
        'event_id',event_id,
        'organization_id',org_id,
        'record_id',rec_id,
        'operation',op,
        'payload',jsonb_build_object(
            'organization_id',org_id,
            'record_id',rec_id,
            'version_id',ver_id,
            'base_version_id',base_id,
            'device_id',dev_id,
            'record_type',rec_type,
            'version',logical_ver,
            'key_version',submitted_key_version,
            'ciphertext',payload->>'ciphertext',
            'nonce',payload->>'nonce',
            'wrapped_data_key',payload->>'wrapped_data_key',
            'wrap_nonce',payload->>'wrap_nonce',
            'content_hash',lower(payload->>'content_hash'),
            'deleted',submitted_deleted
        )
    );
    -- updated_at is intentionally excluded: it is local queue metadata and
    -- does not change the encrypted record or its version semantics.
    incoming_request_hash := encode(
        extensions.digest(
            convert_to(canonical_request::text,'UTF8'),
            'sha256'
        ),
        'hex'
    );

    -- Return the outcome committed by the original transaction.  The head
    -- may since have advanced, so read it independently.
    select e.cursor,e.organization_id,e.applied,e.version_id,e.request_hash
      into existing_cursor,existing_org,existing_applied,existing_version_id,
           existing_request_hash
    from public.sync_events e
    where e.event_id = push_record_event.event_id;
    if existing_cursor is not null then
        if existing_request_hash <> incoming_request_hash then
            raise exception 'event id payload mismatch';
        end if;
        if existing_org <> org_id then
            raise exception 'event id belongs to another organization';
        end if;
        select h.head_version_id into current_head_id
        from public.record_heads h
        where h.organization_id = org_id
          and h.record_id = rec_id;
        return jsonb_build_object(
            'cursor',existing_cursor,
            'duplicate',true,
            'applied',existing_applied,
            'conflict',not existing_applied,
            'version_id',existing_version_id,
            'head_version_id',current_head_id
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
        private.decode_base64url(payload->>'ciphertext'),
        private.decode_base64url(payload->>'nonce'),
        private.decode_base64url(
            payload->>'wrapped_data_key'
        ),
        private.decode_base64url(payload->>'wrap_nonce'),
        submitted_key_version,
        lower(payload->>'content_hash'),
        submitted_deleted
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
               deleted = submitted_deleted,
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
        operation,applied,request_hash
    ) values (
        event_id,org_id,dev_id,rec_id,ver_id,op,applied,
        incoming_request_hash
    ) returning cursor into new_cursor;

    select h.head_version_id into current_head_id
    from public.record_heads h
    where h.organization_id = org_id
      and h.record_id = rec_id;

    return jsonb_build_object(
        'cursor',new_cursor,
        'duplicate',false,
        'applied',applied,
        'conflict',not applied,
        'version_id',ver_id,
        'head_version_id',current_head_id
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
declare
    sync_row record;
    encoded_payload jsonb;
    payload_bytes bigint;
    cumulative_payload_bytes bigint := 0;
    emitted_rows integer := 0;
    bounded_page_size integer :=
        least(greatest(coalesce(page_size,200),1),500);
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
            'ciphertext',
                private.encode_base64url(sync_row.ciphertext),
            'nonce',private.encode_base64url(sync_row.nonce),
            'wrapped_data_key',
                private.encode_base64url(sync_row.wrapped_data_key),
            'wrap_nonce',
                private.encode_base64url(sync_row.wrap_nonce),
            'key_version',sync_row.key_version,
            'content_hash',sync_row.content_hash,
            'deleted',sync_row.deleted
        );
        payload_bytes := octet_length(
            convert_to(encoded_payload::text,'UTF8')
        );
        if emitted_rows > 0
           and cumulative_payload_bytes + payload_bytes > 33554432 then
            exit;
        end if;

        cursor := sync_row.cursor;
        event_id := sync_row.event_id;
        operation := sync_row.operation;
        applied := sync_row.applied;
        payload := encoded_payload;
        cumulative_payload_bytes :=
            cumulative_payload_bytes + payload_bytes;
        emitted_rows := emitted_rows + 1;
        return next;
    end loop;
end;
$$;

revoke all on function private.validate_sync_ciphertext_event(jsonb)
    from public, anon, authenticated;
revoke all on function public.push_record_event(jsonb)
    from public, anon, authenticated;
revoke all on function public.pull_sync_events(uuid,bigint,integer)
    from public, anon, authenticated;

grant execute on function public.push_record_event(jsonb)
    to authenticated;
grant execute on function public.pull_sync_events(uuid,bigint,integer)
    to authenticated;

commit;
