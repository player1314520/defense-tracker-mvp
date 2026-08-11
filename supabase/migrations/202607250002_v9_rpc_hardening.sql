-- Keep privileged implementations outside the exposed Data API schema.
begin;

alter function public.bootstrap_organization(
    text,text,uuid,text,text,text,text
) set schema private;
alter function public.register_device(
    uuid,uuid,text,text,text,text
) set schema private;
alter function public.pair_device(
    uuid,uuid,uuid,integer,text,text,text,text
) set schema private;
alter function public.push_record_event(jsonb) set schema private;
alter function public.resolve_conflict(uuid,uuid,jsonb) set schema private;
alter function public.transition_workflow(
    uuid,uuid,bigint,text,text
) set schema private;
alter function public.begin_key_rotation(
    uuid,integer,bigint
) set schema private;
alter function public.stage_rewrap_batch(uuid,jsonb) set schema private;
alter function public.commit_key_rotation(uuid) set schema private;
alter function public.revoke_device(uuid,uuid) set schema private;
alter function public.revoke_member(uuid,uuid) set schema private;

create function public.bootstrap_organization(
    name_ciphertext text,
    name_nonce text,
    device_id uuid,
    device_public_key text,
    device_name_ciphertext text,
    device_name_nonce text,
    key_algorithm text default 'x25519'
)
returns uuid
language sql
security invoker
set search_path = ''
as $$
    select private.bootstrap_organization(
        name_ciphertext,name_nonce,device_id,device_public_key,
        device_name_ciphertext,device_name_nonce,key_algorithm
    );
$$;

create function public.register_device(
    organization_id uuid,
    device_id uuid,
    key_algorithm text,
    device_public_key text,
    device_name_ciphertext text,
    device_name_nonce text
)
returns uuid
language sql
security invoker
set search_path = ''
as $$
    select private.register_device(
        organization_id,device_id,key_algorithm,device_public_key,
        device_name_ciphertext,device_name_nonce
    );
$$;

create function public.pair_device(
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
language sql
security invoker
set search_path = ''
as $$
    select private.pair_device(
        organization_id,device_id,target_user_id,envelope_key_version,
        envelope_algorithm,ephemeral_public_key,envelope_nonce,
        envelope_ciphertext
    );
$$;

create function public.push_record_event(p_event jsonb)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
    select private.push_record_event(p_event);
$$;

create function public.resolve_conflict(
    conflict_id uuid,
    expected_head_version_id uuid,
    resolution_event jsonb
)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
    select private.resolve_conflict(
        conflict_id,expected_head_version_id,resolution_event
    );
$$;

create function public.transition_workflow(
    organization_id uuid,
    record_id uuid,
    expected_version bigint,
    target_state text,
    content_hash text
)
returns bigint
language sql
security invoker
set search_path = ''
as $$
    select private.transition_workflow(
        organization_id,record_id,expected_version,target_state,content_hash
    );
$$;

create function public.begin_key_rotation(
    organization_id uuid,
    expected_key_version integer,
    expected_count bigint
)
returns uuid
language sql
security invoker
set search_path = ''
as $$
    select private.begin_key_rotation(
        organization_id,expected_key_version,expected_count
    );
$$;

create function public.stage_rewrap_batch(
    rotation_id uuid,
    entries jsonb
)
returns bigint
language sql
security invoker
set search_path = ''
as $$
    select private.stage_rewrap_batch(rotation_id,entries);
$$;

create function public.commit_key_rotation(rotation_id uuid)
returns integer
language sql
security invoker
set search_path = ''
as $$
    select private.commit_key_rotation(rotation_id);
$$;

create function public.revoke_device(
    organization_id uuid,
    device_id uuid
)
returns boolean
language sql
security invoker
set search_path = ''
as $$
    select private.revoke_device(organization_id,device_id);
$$;

create function public.revoke_member(
    organization_id uuid,
    target_user_id uuid
)
returns boolean
language sql
security invoker
set search_path = ''
as $$
    select private.revoke_member(organization_id,target_user_id);
$$;

revoke all on all functions in schema private from public, anon;
grant usage on schema private to authenticated;
grant execute on function private.bootstrap_organization(
    text,text,uuid,text,text,text,text
) to authenticated;
grant execute on function private.register_device(
    uuid,uuid,text,text,text,text
) to authenticated;
grant execute on function private.pair_device(
    uuid,uuid,uuid,integer,text,text,text,text
) to authenticated;
grant execute on function private.push_record_event(jsonb) to authenticated;
grant execute on function private.resolve_conflict(uuid,uuid,jsonb)
    to authenticated;
grant execute on function private.transition_workflow(
    uuid,uuid,bigint,text,text
) to authenticated;
grant execute on function private.begin_key_rotation(
    uuid,integer,bigint
) to authenticated;
grant execute on function private.stage_rewrap_batch(uuid,jsonb)
    to authenticated;
grant execute on function private.commit_key_rotation(uuid) to authenticated;
grant execute on function private.revoke_device(uuid,uuid) to authenticated;
grant execute on function private.revoke_member(uuid,uuid) to authenticated;

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
revoke all on function public.resolve_conflict(uuid,uuid,jsonb)
    from public, anon;
revoke all on function public.transition_workflow(
    uuid,uuid,bigint,text,text
) from public, anon;
revoke all on function public.begin_key_rotation(
    uuid,integer,bigint
) from public, anon;
revoke all on function public.stage_rewrap_batch(uuid,jsonb)
    from public, anon;
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
grant execute on function public.resolve_conflict(uuid,uuid,jsonb)
    to authenticated;
grant execute on function public.transition_workflow(
    uuid,uuid,bigint,text,text
) to authenticated;
grant execute on function public.begin_key_rotation(
    uuid,integer,bigint
) to authenticated;
grant execute on function public.stage_rewrap_batch(uuid,jsonb)
    to authenticated;
grant execute on function public.commit_key_rotation(uuid) to authenticated;
grant execute on function public.revoke_device(uuid,uuid) to authenticated;
grant execute on function public.revoke_member(uuid,uuid) to authenticated;

drop policy key_envelopes_write on public.key_envelopes;
create policy key_envelopes_insert on public.key_envelopes
for insert to authenticated
with check (private.is_org_owner(organization_id));
create policy key_envelopes_update on public.key_envelopes
for update to authenticated
using (private.is_org_owner(organization_id))
with check (private.is_org_owner(organization_id));
create policy key_envelopes_delete on public.key_envelopes
for delete to authenticated
using (private.is_org_owner(organization_id));

create index if not exists organizations_created_by_idx
    on public.organizations(created_by);
create index if not exists memberships_user_idx
    on public.memberships(user_id,organization_id);
create index if not exists devices_user_idx
    on public.devices(user_id,organization_id);
create index if not exists record_heads_head_version_idx
    on public.record_heads(organization_id,record_id,head_version_id);
create index if not exists record_versions_device_idx
    on public.record_versions(organization_id,device_id);
create index if not exists sync_events_device_idx
    on public.sync_events(organization_id,device_id);
create index if not exists sync_events_version_idx
    on public.sync_events(organization_id,record_id,version_id);
create index if not exists conflicts_head_idx
    on public.conflicts(organization_id,record_id,head_version_id);
create index if not exists conflicts_resolved_by_idx
    on public.conflicts(resolved_by) where resolved_by is not null;
create index if not exists encrypted_objects_record_idx
    on public.encrypted_objects(organization_id,record_id,version_id);
create index if not exists encrypted_objects_device_idx
    on public.encrypted_objects(organization_id,device_id);
create index if not exists audit_chain_actor_idx
    on public.audit_chain(actor_user_id);
create index if not exists key_rotations_creator_idx
    on public.key_rotations(created_by);
create index if not exists key_rotation_entries_version_idx
    on public.key_rotation_entries(organization_id,record_id,version_id);
create index if not exists workflow_states_assignee_idx
    on public.workflow_states(assigned_user_id)
    where assigned_user_id is not null;
create index if not exists workflow_states_updated_by_idx
    on public.workflow_states(updated_by);
create index if not exists device_pairings_target_idx
    on public.device_pairings(target_user_id);
create index if not exists device_pairings_creator_idx
    on public.device_pairings(created_by);

commit;
