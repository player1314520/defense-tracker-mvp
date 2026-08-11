# -*- coding: utf-8 -*-
from pathlib import Path


MIGRATIONS = (
    Path(__file__).resolve().parents[1]
    / "supabase"
    / "migrations"
)


def _sql() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(MIGRATIONS.glob("*.sql"))
    ).lower()


def test_cloud_schema_has_no_business_plaintext_columns():
    sql = _sql()

    assert "record_versions" in sql
    assert "ciphertext bytea not null" in sql
    assert "wrapped_data_key bytea not null" in sql
    for forbidden in (
        "body text",
        "content text",
        "original_text",
        "report_body",
        "evidence_body",
    ):
        assert forbidden not in sql


def test_security_definer_helpers_are_not_exposed_in_public_schema():
    sql = _sql()

    assert "create schema if not exists private" in sql
    assert "function private.is_org_member" in sql
    assert "function private.is_org_admin" in sql
    assert "function private.is_org_owner" in sql
    assert "security definer" in sql
    assert "set search_path = ''" in sql
    assert "security definer\nset search_path = public" not in sql
    assert "revoke all on all functions in schema private from public" in sql
    assert "set schema private" in sql
    assert "security invoker" in sql


def test_every_exposed_tenant_table_has_rls_and_a_policy():
    sql = _sql()
    tenant_tables = (
        "organizations",
        "memberships",
        "devices",
        "key_envelopes",
        "recovery_envelopes",
        "record_heads",
        "record_versions",
        "sync_events",
        "sync_wakeups",
        "conflicts",
        "encrypted_objects",
        "workflow_states",
        "audit_chain",
        "key_rotations",
    )
    for table in tenant_tables:
        assert f"alter table public.{table} enable row level security" in sql
        assert f"on public.{table}" in sql


def test_role_constraint_contains_exact_six_roles():
    sql = _sql()

    for role in ("owner", "admin", "collector", "analyst", "editor", "approver"):
        assert f"'{role}'" in sql


def test_cloud_versions_are_append_only_and_sync_cursor_advances_per_event():
    sql = _sql()

    assert "create table if not exists public.record_heads" in sql
    assert "create table if not exists public.record_versions" in sql
    assert "base_version_id uuid" in sql
    assert "create table if not exists public.conflicts" in sql
    assert "cursor bigint generated always as identity" in sql
    assert "create or replace function public.push_record_event" in sql
    assert "for update" not in _policy_block(sql, "record_versions")


def test_cross_tenant_references_use_composite_foreign_keys():
    sql = _sql()

    assert "unique (organization_id, id)" in sql
    assert (
        "foreign key (organization_id, device_id) "
        "references public.devices(organization_id, id)"
    ) in _compact(sql)
    assert (
        "foreign key (organization_id, record_id) "
        "references public.record_heads(organization_id, record_id)"
    ) in _compact(sql)


def test_owner_invariants_and_recovery_are_owner_only():
    sql = _sql()

    assert "create or replace function public.revoke_member" in sql
    assert "cannot revoke the last owner" in sql
    assert "private.is_org_owner(organization_id)" in sql
    recovery = _policy_block(sql, "recovery_envelopes")
    assert "private.is_org_owner" in recovery
    assert "private.is_org_admin" not in recovery


def test_workflow_and_rotation_rpcs_use_expected_versions():
    sql = _sql()

    for function_name in (
        "transition_workflow",
        "begin_key_rotation",
        "stage_rewrap_batch",
        "commit_key_rotation",
        "resolve_conflict",
    ):
        assert f"function public.{function_name}" in sql
    assert "expected_version" in sql
    assert "expected_key_version" in sql


def test_storage_objects_are_private_immutable_and_org_scoped():
    sql = _sql()

    assert "'defense-v9-encrypted'" in sql
    assert "create policy v9_storage_select" in sql
    assert "create policy v9_storage_insert" in sql
    assert "create policy v9_storage_delete" in sql
    assert "create policy v9_storage_update" not in sql
    assert "private.path_org_uuid(name)" in sql
    assert "ciphertext_sha256" in sql


def test_existing_personal_organization_can_keep_its_uuid_without_public_definer():
    sql = _sql()
    assert "requested_organization_id uuid" in sql
    assert "new_org uuid := requested_organization_id" in sql
    assert "security invoker" in sql


def test_realtime_is_metadata_only_and_authenticated_grants_are_minimal():
    sql = _sql()
    compact = _compact(sql)

    assert "create table if not exists public.sync_wakeups" in sql
    assert "latest_cursor bigint not null" in sql
    assert "after insert on public.sync_events" in sql
    assert "alter publication supabase_realtime" in sql
    assert "revoke all on all tables in schema public from authenticated" in sql
    assert "grant insert, delete on public.encrypted_objects to authenticated" in compact
    assert "grant update on public.organizations to authenticated" in compact
    assert "grant update on public.record_versions" not in compact


def _compact(value: str) -> str:
    return " ".join(value.split())


def _policy_block(sql: str, table: str) -> str:
    lines = sql.splitlines()
    matching = [
        line
        for index, line in enumerate(lines)
        if (
            f"on public.{table}" in line
            or (
                index > 0
                and f"on public.{table}" in lines[index - 1]
            )
        )
    ]
    return "\n".join(matching)


def _hardening_sql() -> str:
    return (
        MIGRATIONS / "202607260007_v9_security_hardening.sql"
    ).read_text(encoding="utf-8").lower()


def _hardening_function(function_name: str) -> str:
    sql = _hardening_sql()
    start = sql.index(f"create or replace function public.{function_name}")
    end = sql.index("$$;", start) + 3
    return sql[start:end]


def _signed_workflow_sql() -> str:
    return (
        MIGRATIONS / "202607260008_v9_signed_workflow_hardening.sql"
    ).read_text(encoding="utf-8").lower()


def _push_idempotency_sql() -> str:
    return (
        MIGRATIONS / "202607260009_v9_push_idempotency.sql"
    ).read_text(encoding="utf-8").lower()


def _conflict_resolution_sql() -> str:
    return (
        MIGRATIONS / "202607260010_v9_conflict_resolution_binding.sql"
    ).read_text(encoding="utf-8").lower()


def _signed_object_protection_sql() -> str:
    return (
        MIGRATIONS / "202607260012_v9_signed_object_protection.sql"
    ).read_text(encoding="utf-8").lower()


def _signed_object_null_hardening_sql() -> str:
    return (
        MIGRATIONS / "202607260013_v9_signed_object_null_hardening.sql"
    ).read_text(encoding="utf-8").lower()


def _performance_indexes_sql() -> str:
    return (
        MIGRATIONS / "202607300014_v9_performance_indexes.sql"
    ).read_text(encoding="utf-8").lower()


def _secure_invitations_sql() -> str:
    return (
        MIGRATIONS / "202607300015_v9_secure_member_invitations.sql"
    ).read_text(encoding="utf-8").lower()


def test_performance_indexes_cover_every_advisor_foreign_key():
    sql = _performance_indexes_sql()
    compact = _compact(sql)
    expected = (
        (
            "private.encrypted_object_delete_requests "
            "(organization_id, record_id, version_id)"
        ),
        "private.encrypted_object_delete_requests (finalized_by)",
        "private.encrypted_object_delete_requests (requested_by)",
        (
            "private.signed_publication_objects "
            "(organization_id, publication_id, record_id, record_version_id)"
        ),
        (
            "private.signed_publication_versions "
            "(organization_id, record_id, record_version_id)"
        ),
        "private.signed_publication_versions (signed_by)",
        (
            "private.snapshot_import_items "
            "(import_id, organization_id)"
        ),
        (
            "private.snapshot_import_items "
            "(organization_id, record_id, version_id)"
        ),
        "private.snapshot_imports (created_by)",
        (
            "public.workflow_states "
            "(organization_id, record_id, bound_version_id)"
        ),
    )

    assert compact.count("create index if not exists") == len(expected)
    for target in expected:
        assert f" on {target}" in compact
    assert "drop index" not in compact


def test_sync_pull_encodes_inside_a_member_checked_definer_rpc():
    block = _hardening_function("pull_sync_events")
    sql = _hardening_sql()

    assert "security definer" in block
    assert "set search_path = ''" in block
    assert "from public.memberships m" in block
    assert "m.user_id = (select auth.uid())" in block
    assert "m.status = 'active'" in block
    assert "private.encode_base64url" in block
    assert (
        "revoke all on function private.encode_base64url(bytea) "
        "from public, anon, authenticated"
    ) in _compact(sql)
    assert "grant execute on function private.encode_base64url" not in sql


def test_workflow_transition_is_bound_to_the_current_publishable_head_hash():
    block = _hardening_function("transition_workflow")
    compact = _compact(block)

    assert (
        "current_head.record_type not in ( 'document','publication_item' )"
        in compact
    )
    assert "current_head.head_version_id is null" in compact
    assert (
        "v.version_id = current_head.head_version_id"
    ) in compact
    assert "head_content_hash <> submitted_hash" in compact
    assert "raise exception 'content hash does not match current head'" in block
    assert "extensions.digest(" in block


def test_signed_workflow_increment_enforces_immutability_and_state_graph():
    sql = _signed_workflow_sql()
    compact = _compact(sql)

    assert "function private.guard_signed_record_version()" in compact
    assert "before insert on public.record_versions" in compact
    assert "raise exception 'signed record is immutable until recalled'" in sql
    assert "function private.guard_workflow_transition()" in compact
    assert (
        "before insert or update on public.workflow_states"
        in compact
    )
    assert "raise exception 'invalid workflow transition'" in sql
    assert "raise exception 'pending approval content hash changed'" in sql
    assert "raise exception 'open conflict blocks signing'" in sql
    assert "from public.conflicts c" in compact
    assert "c.status = 'open'" in compact
    assert "set search_path = ''" in sql
    assert (
        "revoke all on function private.guard_signed_record_version() "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "revoke all on function private.guard_workflow_transition() "
        "from public, anon, authenticated"
    ) in compact


def test_key_rotation_serializes_writes_and_revalidates_the_locked_version_set():
    push = _hardening_function("push_record_event")
    begin = _hardening_function("begin_key_rotation")
    stage = _hardening_function("stage_rewrap_batch")
    commit = _hardening_function("commit_key_rotation")
    push_compact = _compact(push)
    commit_compact = _compact(commit)

    assert "from public.organizations o" in push
    assert "for share" in push
    assert "r.status = 'staging'" in push_compact
    assert "raise exception 'key rotation in progress'" in push
    assert "for update" in begin
    assert "v.key_version = current_version" in _compact(begin)
    assert "v.key_version = rotation.from_key_version" in _compact(stage)
    assert "for update" in commit
    assert "actual_count <> rotation.expected_count" in commit_compact
    assert "raise exception 'rewrap target set changed'" in commit
    assert "updated_count <> actual_count" in commit_compact
    assert "remaining_old_count <> 0" in commit_compact


def test_revoke_member_locks_the_organization_before_counting_owners():
    block = _hardening_function("revoke_member")
    compact = _compact(block)

    organization_lock = compact.index("from public.organizations o")
    owner_count = compact.index("select count(*) into owner_count")
    assert "for update" in compact[organization_lock:owner_count]
    assert organization_lock < owner_count
    assert "cannot revoke the last owner" in block


def test_first_cloud_snapshot_preserves_a_positive_local_logical_version():
    block = _hardening_function("push_record_event")
    compact = _compact(block)

    assert "op not in ('upsert','delete','snapshot')" in compact
    assert "logical_ver <= 0" in compact
    assert "if op = 'snapshot'" in compact
    assert "elsif logical_ver <> 1" in compact
    assert "raise exception 'snapshot requires a missing record'" in block
    assert (
        "current_head.head_version_id is null "
        "and base_id is null and logical_ver >= 1"
    ) in compact
    assert "base_logical_version + 1 <> logical_ver" in compact
    assert "raise exception 'logical version is not based on base version'" in block


def test_push_retry_returns_the_original_outcome_and_current_head():
    sql = _push_idempotency_sql()
    compact = _compact(sql)

    assert "create or replace function public.push_record_event" in sql
    assert "security definer" in sql
    assert "set search_path = ''" in sql
    assert (
        "select e.cursor,e.organization_id,e.applied,e.version_id,"
        "e.request_hash"
    ) in compact
    assert (
        "into existing_cursor,existing_org,existing_applied,"
        "existing_version_id"
    ) in compact
    assert "'applied',existing_applied" in compact
    assert "'version_id',existing_version_id" in compact
    assert compact.count("'head_version_id',current_head_id") == 2
    assert "'applied',applied" in compact
    assert "'version_id',ver_id" in compact
    assert (
        "revoke all on function public.push_record_event(jsonb) "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "grant execute on function public.push_record_event(jsonb) "
        "to authenticated"
    ) in compact


def test_push_idempotency_hash_is_fail_closed_and_payload_bound():
    sql = _push_idempotency_sql()
    compact = _compact(sql)
    duplicate_lookup = compact.index("from public.sync_events e")

    assert "if exists ( select 1 from public.sync_events" in compact
    assert "raise exception 'request hash migration requires empty sync_events'" in sql
    assert "add column if not exists request_hash text" in compact
    assert "alter column request_hash set not null" in compact
    assert "request_hash ~ '^[0-9a-f]{64}$'" in sql

    advisory_lock = compact.index("pg_advisory_xact_lock")
    hash_build = compact.index("canonical_request := jsonb_build_object")
    assert advisory_lock < hash_build < duplicate_lookup
    assert "extensions.digest(" in sql
    assert "'sha256'" in sql
    for semantic_field in (
        "'event_id'",
        "'organization_id'",
        "'record_id'",
        "'operation'",
        "'version_id'",
        "'base_version_id'",
        "'device_id'",
        "'record_type'",
        "'version'",
        "'key_version'",
        "'ciphertext'",
        "'nonce'",
        "'wrapped_data_key'",
        "'wrap_nonce'",
        "'content_hash'",
        "'deleted'",
    ):
        assert semantic_field in compact[hash_build:duplicate_lookup]
    assert "updated_at is intentionally excluded" in sql

    assert "e.request_hash" in compact
    assert "existing_request_hash <> incoming_request_hash" in compact
    assert "raise exception 'event id payload mismatch'" in sql
    assert "operation,applied,request_hash ) values" in compact
    assert (
        "event_id,org_id,dev_id,rec_id,ver_id,op,applied,"
    ) in compact
    assert "incoming_request_hash ) returning cursor" in compact


def test_push_rejects_unknown_keys_and_owner_gates_snapshot():
    sql = _push_idempotency_sql()
    compact = _compact(sql)

    assert compact.count("jsonb_object_keys(") >= 2
    assert "raise exception 'unsupported event field'" in sql
    assert "raise exception 'unsupported payload field'" in sql
    assert "raise exception 'missing event field'" in sql
    assert "raise exception 'missing payload field'" in sql
    assert "if op = 'snapshot' and not private.is_org_owner(org_id)" in compact
    assert "raise exception 'snapshot requires owner'" in sql


def test_conflict_resolution_binds_the_event_and_version_to_the_target_record():
    sql = _conflict_resolution_sql()
    compact = _compact(sql)

    assert "create or replace function public.resolve_conflict" in sql
    assert "security definer" in sql
    assert "set search_path = ''" in sql
    assert "from public.conflicts c" in sql
    assert "for update" in sql
    assert "private.can_write_record(" in sql
    assert "target.organization_id" in sql
    assert "target.record_id" in sql
    assert "head changed during resolution" in sql
    assert "resolution event identity mismatch" in sql
    assert "from public.sync_events e" in sql
    assert "join public.record_versions v" in sql
    assert "e.organization_id = target.organization_id" in compact
    assert "e.record_id = target.record_id" in compact
    assert "e.applied = true" in compact
    assert "e.version_id = (pushed->>'version_id')::uuid" in compact
    assert "v.organization_id = target.organization_id" in compact
    assert "v.record_id = target.record_id" in compact
    assert "resolution event binding mismatch" in sql
    assert "resolution event is not current target version" in sql
    assert "resolution_version_id=resolved_version_id" in compact
    assert (
        "revoke all on function public.resolve_conflict(uuid,uuid,jsonb) "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "grant execute on function public.resolve_conflict(uuid,uuid,jsonb) "
        "to authenticated"
    ) in compact


def test_resolved_conflict_retry_is_idempotent_only_for_the_committed_event():
    sql = _conflict_resolution_sql()
    compact = _compact(sql)

    conflict_lock = compact.index("from public.conflicts c")
    identity_check = compact.index("resolution event identity mismatch")
    resolved_branch = compact.index("if target.status = 'resolved' then")
    push_call = compact.index("pushed := public.push_record_event")

    assert "c.status = 'open'" not in compact[conflict_lock:identity_check]
    assert identity_check < resolved_branch < push_call
    assert "target.resolution_version_id is null" in compact
    assert "e.event_id = resolution_event_id" in compact
    assert "e.organization_id = target.organization_id" in compact
    assert "e.record_id = target.record_id" in compact
    assert "e.applied = true" in compact
    assert "e.version_id = target.resolution_version_id" in compact
    assert "e.request_hash = incoming_request_hash" in compact
    assert "v.organization_id = target.organization_id" in compact
    assert "v.record_id = target.record_id" in compact
    assert "jsonb_typeof(resolution_event) <> 'object'" in compact
    assert "unsupported resolution event field" in sql
    assert "unsupported resolution payload field" in sql
    assert "canonical_request := jsonb_build_object(" in compact
    assert "extensions.digest(" in compact
    assert "resolved conflict retry mismatch" in sql
    assert "resolved conflict head changed" in sql
    assert "'applied',true" in compact
    assert "'duplicate',true" in compact
    assert "'version_id',target.resolution_version_id" in compact
    assert "'head_version_id',target.resolution_version_id" in compact
    assert "'resolved_conflict_id',resolve_conflict.conflict_id" in compact
    assert "if target.status <> 'open' then" in compact


def test_signed_workflow_binds_current_head_and_physical_object_manifest():
    sql = _signed_object_protection_sql()
    compact = _compact(sql)

    assert "add column if not exists bound_version_id uuid" in compact
    assert "add column if not exists object_manifest_hash text" in compact
    assert "add column if not exists object_count bigint" in compact
    assert (
        "foreign key (organization_id,record_id,bound_version_id) "
        "references public.record_versions"
    ) in compact
    assert "private.current_object_manifest" in sql
    assert "left join storage.objects" in compact
    assert "physical_count <> manifest.object_count" in compact
    assert "new.state = 'pending_approval'" in compact
    assert "new.bound_version_id := current_head.head_version_id" in compact
    assert "new.state = 'signed'" in compact
    assert "old.bound_version_id <> current_head.head_version_id" in compact
    assert "pending approval object manifest changed" in sql
    assert "new.state = 'recalled'" in compact


def test_signed_object_delete_requires_ticket_storage_delete_and_finalize():
    sql = _signed_object_protection_sql()
    compact = _compact(sql)

    assert "create table private.encrypted_object_delete_requests" in sql
    assert "create or replace function public.begin_encrypted_object_delete" in sql
    assert "create or replace function public.finalize_encrypted_object_delete" in sql
    assert "actor_role not in ('owner','admin')" in compact
    assert "protected workflow objects cannot be deleted" in sql
    assert "revoke delete on public.encrypted_objects from authenticated" in compact
    assert "drop policy if exists encrypted_objects_delete" in compact
    assert "drop policy if exists v9_storage_delete on storage.objects" in compact
    assert "private.can_delete_encrypted_storage_object(name)" in compact
    assert (
        "before insert or update or delete on public.encrypted_objects"
        in compact
    )
    assert "encrypted object metadata is immutable" in sql
    assert (
        "grant execute on function "
        "private.can_delete_encrypted_storage_object(text) to authenticated"
        in compact
    )
    assert (
        "current_setting( 'defense_tracker.object_delete_request',true )"
        in compact
    )
    assert "storage object must be deleted before metadata finalize" in sql
    assert "object_delete_requested" in sql
    assert "object_deleted" in sql
    assert (
        "revoke all on function public.begin_encrypted_object_delete(uuid,uuid) "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "grant execute on function public.finalize_encrypted_object_delete(uuid) "
        "to authenticated"
    ) in compact


def test_signed_object_manifest_checks_are_null_safe():
    sql = _signed_object_null_hardening_sql()
    compact = _compact(sql)

    assert "object_manifest_hash is not null" in compact
    assert "old.bound_version_id is distinct from" in compact
    assert "old.object_count is distinct from" in compact
    assert "old.object_manifest_hash is distinct from" in compact
    assert "drop constraint if exists workflow_states_object_manifest_check" in compact
    assert "private.guard_signed_object_manifest_not_null" in sql
    assert (
        "revoke all on function "
        "private.guard_signed_object_manifest_not_null() "
        "from public, anon, authenticated"
    ) in compact


def test_storage_delete_is_atomically_audited_and_remains_finalizable():
    sql = _signed_object_null_hardening_sql()
    compact = _compact(sql)

    assert "'storage_deleted'" in sql
    assert "storage_deleted_at timestamptz" in compact
    assert "finalized_by uuid references auth.users(id)" in compact
    assert "clock_timestamp()" in compact
    assert (
        "encrypted_object_delete_requests_one_active_object"
        in compact
    )
    assert "encrypted_object_delete_requests_lifecycle_check" in compact
    assert "row_number() over (" in compact
    assert "set status = 'cancelled'" in compact
    assert "where status = 'completed'" in compact
    assert "metadata_deleted_at = coalesce(" in compact
    helper_start = compact.index(
        "create or replace function "
        "private.can_delete_encrypted_storage_object"
    )
    finalize_start = compact.index(
        "create or replace function "
        "public.finalize_encrypted_object_delete"
    )
    can_insert_start = compact.index(
        "create or replace function "
        "private.can_insert_encrypted_storage_object",
        helper_start,
    )
    helper = compact[helper_start:can_insert_start]
    assert "returns boolean language plpgsql volatile security definer" in helper
    assert "for update" in helper
    assert (
        "storage.allow_any_operation( "
        "array['object.delete','object.delete_many']"
    ) in helper
    assert "set status = 'storage_deleted'" in helper
    assert "private.append_object_audit" not in helper
    snapshot_read = helper.index("select r.* into request_snapshot")
    ticket_lock = helper.index("where r.id = request_snapshot.id")
    assert snapshot_read < ticket_lock
    assert helper.count("for update") == 1
    assert "from public.record_heads h" not in helper
    assert "select w.* into current_state" in helper
    assert "select o.* into target_object" in helper
    assert (
        "r.status in ( "
        "'requested','storage_deleted','orphaned','completed' )"
    ) in helper
    assert "defense_tracker.storage_delete_request" in helper
    assert "return transaction_request = target_request.id::text" in helper
    finalize = compact[finalize_start:]
    assert "target_request.status = 'completed'" in finalize
    assert (
        "target_request.status not in ( "
        "'requested','storage_deleted','orphaned' )"
    ) in finalize
    assert "object_storage_deleted_recovered:" in finalize
    assert "object_storage_deleted:" in finalize
    assert "object_completed_orphan_cleanup_confirmed:" in finalize
    assert "last_cleanup_attempt_at" in finalize
    assert "last_cleanup_confirmed_at" in finalize
    finalize_ticket_lock = finalize.index(
        "where r.id = request_snapshot.id"
    )
    assert "for update nowait" in finalize[
        finalize_ticket_lock:finalize_ticket_lock + 800
    ]
    assert "when lock_not_available then" in finalize
    assert "object deletion already in progress" in finalize
    assert "and r.requested_by = actor" not in finalize
    assert "set finalized_by = actor" in finalize
    assert "list_pending_encrypted_object_deletes" in compact
    assert "limit 200" in finalize
    assert (
        "q.last_cleanup_attempt_at > q.last_cleanup_confirmed_at"
        in finalize
    )
    assert "private.can_insert_encrypted_storage_object(name)" in compact
    assert (
        "grant execute on function "
        "public.list_pending_encrypted_object_deletes(uuid) "
        "to authenticated"
    ) in compact


def test_signed_object_history_is_immutable_across_recall_and_reediting():
    sql = _signed_object_null_hardening_sql()
    compact = _compact(sql)

    assert "create table private.signed_publication_versions" in sql
    assert "create table private.signed_publication_objects" in sql
    assert (
        "references public.encrypted_objects(organization_id,id)"
        in compact
    )
    assert "create or replace function private.capture_signed_publication" in sql
    assert "new.state <> 'signed'" in compact
    assert "old.state <> 'pending_approval'" in compact
    assert "new.bound_version_id" in compact
    assert "new.object_manifest_hash" in compact
    assert "new.object_count" in compact
    assert "after update on public.workflow_states" in compact
    assert "private.capture_signed_publication()" in compact
    assert "state in ('signed','recalled')" in compact
    assert "from public.audit_chain a" in compact
    assert "a.event_type = 'workflow:signed'" in compact
    assert "existing signed workflow history requires explicit migration" in sql
    assert compact.count("private.signed_publication_objects") >= 7
    assert "historically signed objects cannot be deleted" in sql
    assert "p.object_id = target_request.object_id" in compact
    assert (
        "revoke all on table private.signed_publication_versions "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "revoke all on table private.signed_publication_objects "
        "from public, anon, authenticated"
    ) in compact


def test_storage_reupload_becomes_inaccessible_and_retryable_orphan():
    sql = _signed_object_null_hardening_sql()
    compact = _compact(sql)

    insert_start = compact.index(
        "create or replace function "
        "private.can_insert_encrypted_storage_object"
    )
    policy_start = compact.index(
        "create or replace function "
        "private.can_select_encrypted_storage_delete"
    )
    insert_helper = compact[insert_start:policy_start]
    assert "returns boolean language plpgsql volatile security definer" in (
        insert_helper
    )
    assert "for share" not in insert_helper
    assert "r.status <> 'cancelled'" in insert_helper
    assert "r.metadata_deleted_at is not null" in insert_helper
    assert "language sql stable" not in insert_helper

    assert "guard_v9_encrypted_storage_write" not in sql
    assert "before insert or update on storage.objects" not in compact
    assert "after insert or update on storage.objects" not in compact
    assert "drop policy if exists v9_storage_select" in compact
    assert (
        "create policy v9_storage_download_select on storage.objects"
        in compact
    )
    assert (
        "create policy v9_storage_upload_return_select on storage.objects"
        in compact
    )
    assert (
        "create policy v9_storage_delete_internal_select on storage.objects"
        in compact
    )
    download_start = compact.index(
        "create policy v9_storage_download_select"
    )
    upload_start = compact.index(
        "create policy v9_storage_upload_return_select"
    )
    delete_select_start = compact.index(
        "create policy v9_storage_delete_internal_select"
    )
    finalize_start = compact.index(
        "create or replace function public.finalize_encrypted_object_delete"
    )
    download_policy = compact[download_start:upload_start]
    upload_policy = compact[upload_start:delete_select_start]
    delete_select_policy = compact[delete_select_start:finalize_start]
    assert (
        "array[ 'object.get_authenticated_info', "
        "'object.get_authenticated' ]"
    ) in download_policy
    assert "object.sign" not in download_policy
    assert "array['object.upload']" in upload_policy
    assert "private.can_insert_encrypted_storage_object(name)" in (
        upload_policy
    )
    assert (
        "array['object.delete','object.delete_many']"
        in delete_select_policy
    )
    assert "private.can_select_encrypted_storage_delete(name)" in (
        delete_select_policy
    )
    assert "from public.encrypted_objects o" in compact
    assert "o.storage_path = name" in compact
    assert "deleted object identifiers cannot be reused" in sql
    assert (
        "r.status in ( 'storage_deleted','orphaned','completed' )"
        in compact
    )
    assert "or r.metadata_deleted_at is not null" in compact
    assert "metadata_deleted_at timestamptz" in compact
    assert "orphaned_at timestamptz" in compact
    assert "'orphaned'" in sql
    assert "object_storage_orphaned:" in sql
    assert "target_request.status in ('requested','orphaned')" in compact
    assert (
        "status in ('requested','storage_deleted','orphaned')"
    ) in compact
    assert "storage object must be deleted before metadata finalize" not in (
        sql
    )
    assert (
        "storage.allow_any_operation( "
        "array['object.delete','object.delete_many']"
    ) in compact
    delete_start = compact.index(
        "create or replace function "
        "private.can_delete_encrypted_storage_object"
    )
    delete_end = compact.index(
        "create or replace function "
        "private.can_insert_encrypted_storage_object"
    )
    delete_helper = compact[delete_start:delete_end]
    assert (
        "target_request.status in ('orphaned','completed')"
        in delete_helper
    )
    assert "from public.encrypted_objects o" in delete_helper
    assert "o.id = target_request.object_id" in delete_helper
    assert "o.storage_path = target_request.storage_path" in delete_helper


def test_active_object_delete_blocks_approval_and_can_be_cancelled_safely():
    sql = _signed_object_null_hardening_sql()
    compact = _compact(sql)

    guard_start = compact.index(
        "create or replace function private.guard_workflow_transition()"
    )
    guard_end = compact.index(
        "create table private.signed_publication_versions",
        guard_start,
    )
    guard = compact[guard_start:guard_end]
    ticket_check = guard.index(
        "from private.encrypted_object_delete_requests r"
    )
    pending_branch = guard.index("if new.state = 'pending_approval'")
    assert ticket_check < pending_branch
    assert (
        "r.status in ('requested','storage_deleted','orphaned')"
        in guard
    )
    assert "active object deletion blocks workflow approval" in guard

    cancel_start = compact.index(
        "create or replace function "
        "public.cancel_encrypted_object_delete"
    )
    delete_helper_start = compact.index(
        "create or replace function "
        "private.can_delete_encrypted_storage_object",
        cancel_start,
    )
    cancel = compact[cancel_start:delete_helper_start]
    begin_start = compact.index(
        "create or replace function public.begin_encrypted_object_delete"
    )
    begin = compact[begin_start:cancel_start]
    begin_ticket = begin.index("select r.* into active_request")
    assert "for update nowait" in begin[begin_ticket:]
    assert "when lock_not_available then" in begin
    assert "object deletion already in progress" in begin
    organization_lock = cancel.index("from public.organizations org")
    ticket_lock = cancel.index("where r.id = request_snapshot.id")
    assert organization_lock < ticket_lock
    assert "for update nowait" in cancel
    assert "when lock_not_available then" in cancel
    assert "object deletion already in progress" in cancel
    assert "m.role in ('owner','admin')" in cancel
    assert "target_request.status <> 'requested'" in cancel
    assert "target_request.storage_deleted_at is not null" in cancel
    assert "target_request.metadata_deleted_at is not null" in cancel
    assert "target_request.cleanup_attempts <> 0" in cancel
    assert "set status = 'cancelled'" in cancel
    assert "object_delete_cancelled:" in cancel
    assert (
        "revoke all on function "
        "public.cancel_encrypted_object_delete(uuid) "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "grant execute on function "
        "public.cancel_encrypted_object_delete(uuid) to authenticated"
    ) in compact


def test_invited_memberships_store_only_bounded_invitation_metadata():
    sql = _secure_invitations_sql()
    compact = _compact(sql)

    assert "drop constraint if exists memberships_status_check" in compact
    assert "status in ('active','invited','revoked')" in compact
    for column in (
        "invited_by uuid",
        "invited_at timestamptz",
        "invite_expires_at timestamptz",
        "invitation_request_id uuid",
        "accepted_at timestamptz",
    ):
        assert f"add column if not exists {column}" in compact
    assert "create table private.member_invitation_requests" in compact
    assert "email_sha256 text not null" in compact
    assert "email text" not in sql
    assert (
        "revoke all on table private.member_invitation_requests"
        in compact
    )
    assert "unique (organization_id,id)" in compact
    assert (
        "foreign key ( organization_id,invitation_request_id ) "
        "references private.member_invitation_requests( "
        "organization_id,id )"
    ) in compact


def test_invitation_rpcs_lock_org_and_revalidate_active_inviter():
    sql = _secure_invitations_sql()
    compact = _compact(sql)

    for name in (
        "begin_member_invitation",
        "cancel_member_invitation",
    ):
        private_start = compact.index(
            f"create or replace function private.{name}"
        )
        private_end = compact.index("$$;", private_start) + 3
        block = compact[private_start:private_end]
        org_lock = block.index("from public.organizations o")
        role_check = block.index("from public.memberships m")
        assert org_lock < role_check
        assert "for update" in block[org_lock:role_check]
        assert "m.status = 'active'" in block
        assert "actor_role not in ('owner','admin')" in block
        assert "security definer set search_path = ''" in block
        if name == "begin_member_invitation":
            assert "p_role = 'owner' and actor_role <> 'owner'" in block
        else:
            assert (
                "target_request.role = 'owner' "
                "and actor_role <> 'owner'"
            ) in block
    assert (
        "grant execute on function public.begin_member_invitation"
        in compact
    )
    assert "to authenticated" in compact
    assert "from public, anon, authenticated" in compact


def test_accept_binds_authenticated_email_before_creating_invited_membership():
    sql = _secure_invitations_sql()
    compact = _compact(sql)
    start = compact.index(
        "create or replace function private.accept_member_invitation"
    )
    end = compact.index("$$;", start) + 3
    block = compact[start:end]

    assert "actor uuid := (select auth.uid())" in block
    assert "from auth.users u" in block
    assert "extensions.digest" in block
    assert "r.email_sha256 = actor_email_hash" in block
    assert "order by r.organization_id,r.id" in block
    assert "from public.organizations o" in block
    assert "for update" in block
    assert "inviter_role not in ('owner','admin')" in block
    assert "status = 'invited'" in block
    assert "invitation_request_id = target_request.id" in block
    assert "set status = 'active'" not in block
    assert "'accepted_count'" in block
    assert "'invitations'" not in block


def test_invited_user_can_register_pending_device_and_pairing_is_atomic():
    sql = _secure_invitations_sql()
    compact = _compact(sql)
    register_start = compact.index(
        "create or replace function private.register_device"
    )
    pair_start = compact.index(
        "create or replace function private.pair_device",
        register_start,
    )
    register = compact[register_start:pair_start]
    pair_end = compact.index(
        "create or replace function public.begin_member_invitation",
        pair_start,
    )
    pair = compact[pair_start:pair_end]

    assert "m.user_id = actor" in register
    assert "m.status = 'invited'" in register
    assert "m.invite_expires_at > now()" in register
    assert "'pending'" in register
    assert "from public.organizations o" in pair
    assert "for update" in pair
    assert "target_membership.status = 'invited'" in pair
    assert "target_membership.invite_expires_at <= now()" in pair
    assert "target_membership.role = 'owner'" in pair
    assert "actor_role <> 'owner'" in pair
    assert "insert into public.key_envelopes" in pair
    assert "update public.devices" in pair
    assert "update public.memberships" in pair
    assert "set status = 'active'" in pair


def test_invited_membership_and_device_rls_are_self_only():
    sql = _secure_invitations_sql()
    compact = _compact(sql)

    assert "drop policy if exists memberships_select" in compact
    assert "drop policy if exists devices_select" in compact
    assert "drop policy if exists organizations_select" in compact
    assert "private.is_org_member(organizations.id)" in compact
    assert "own_membership.user_id = (select auth.uid())" in compact
    assert "own_membership.status = 'invited'" in compact
    assert "own_membership.invite_expires_at > now()" in compact
    assert "memberships.user_id = (select auth.uid())" in compact
    assert "memberships.status = 'invited'" in compact
    assert "memberships.invite_expires_at > now()" in compact
    assert "private.is_org_admin(memberships.organization_id)" in compact
    assert "private.can_read_device" in compact
    assert "actor_membership.role in ('owner','admin')" in compact
    assert "target_user = (select auth.uid())" in compact
    assert "m.status = 'active'" in compact
    assert "m.status = 'invited'" in compact
    assert "m.invite_expires_at > now()" in compact
    assert (
        "memberships.status <> 'invited' and "
        "private.is_org_member(memberships.organization_id)"
    ) not in compact
    assert "target_membership.status <> 'invited'" not in compact


def test_invited_owner_does_not_count_toward_last_owner_invariant():
    hardening = _hardening_function("revoke_member")
    compact = _compact(hardening)

    assert "m.role = 'owner'" in compact
    assert "m.status = 'active'" in compact
    assert "cannot revoke the last owner" in hardening


def test_revoke_member_handles_invited_without_weakening_owner_invariants():
    sql = _secure_invitations_sql()
    compact = _compact(sql)
    start = compact.index(
        "create or replace function private.revoke_member"
    )
    end = compact.index("$$;", start) + 3
    block = compact[start:end]

    assert "from public.organizations o" in block
    assert "for update" in block
    assert "target_status not in ('active','invited')" in block
    assert "target_role = 'owner' and actor_role <> 'owner'" in block
    assert (
        "target_role = 'owner' and target_status = 'active'"
        in block
    )
    assert "m.role = 'owner'" in block
    assert "m.status = 'active'" in block
    assert "cannot revoke the last owner" in block
    assert "devices.status <> 'revoked'" in block
    assert "set status = 'revoked'" in block
    assert (
        "create or replace function public.revoke_member"
        in compact
    )
    assert "select private.revoke_member(" in compact
    assert (
        "grant execute on function private.revoke_member(uuid,uuid) "
        "to authenticated"
    ) in compact


def test_accept_member_invitation_is_authenticated_only_and_parameterless():
    sql = _secure_invitations_sql()
    compact = _compact(sql)
    private_start = compact.index(
        "create or replace function private.accept_member_invitation()"
    )
    private_end = compact.index("$$;", private_start) + 3
    private_block = compact[private_start:private_end]
    public_start = compact.index(
        "create or replace function public.accept_member_invitation()"
    )
    public_end = compact.index("$$;", public_start) + 3
    public_block = compact[public_start:public_end]

    assert "security definer set search_path = ''" in private_block
    assert "returns jsonb" in private_block
    assert "jsonb_build_object('accepted_count',accepted_count)" in (
        private_block
    )
    assert "security invoker set search_path = ''" in public_block
    assert "select private.accept_member_invitation()" in public_block
    assert (
        "revoke all on function "
        "private.accept_member_invitation() "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "revoke all on function "
        "public.accept_member_invitation() "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "grant execute on function "
        "private.accept_member_invitation() to authenticated"
    ) in compact
    assert (
        "grant execute on function "
        "public.accept_member_invitation() to authenticated"
    ) in compact
    assert "lookup_invitation_auth_user" not in sql


def test_invitation_begin_is_idempotent_for_retried_registration():
    sql = _secure_invitations_sql()
    compact = _compact(sql)
    start = compact.index(
        "create or replace function private.begin_member_invitation"
    )
    end = compact.index("$$;", start) + 3
    block = compact[start:end]

    assert "existing_request private.member_invitation_requests%rowtype" in block
    assert "for update" in block
    assert "return existing_request.id" in block
    assert "r.status = 'requested'" in block
    assert "invitation already pending" not in block
    assert "user already belongs to organization" not in block
    assert "return gen_random_uuid()" in block


def test_invited_pending_device_is_bound_and_bounded():
    sql = _secure_invitations_sql()
    compact = _compact(sql)
    register_start = compact.index(
        "create or replace function private.register_device"
    )
    register_end = compact.index("$$;", register_start) + 3
    register = compact[register_start:register_end]
    pair_start = compact.index(
        "create or replace function private.pair_device"
    )
    pair_end = compact.index("$$;", pair_start) + 3
    pair = compact[pair_start:pair_end]

    assert "add column if not exists invitation_request_id uuid" in compact
    assert (
        "foreign key ( organization_id,invitation_request_id ) "
        "references private.member_invitation_requests( "
        "organization_id,id )"
    ) in compact
    assert "pending_device_count" in register
    assert "invited member already has pending device" in register
    assert "active member pending device limit reached" in register
    assert "octet_length(decoded_public_key)" in register
    assert "octet_length(decoded_name_nonce) <> 12" in register
    assert "invitation_request_id" in register
    assert "target_device_invitation_id" in pair
    assert "is distinct from target_membership.invitation_request_id" in pair
    assert "envelope field size limit exceeded" in pair


def test_auth_user_deletion_is_nonblocking_and_keeps_audit_ids():
    sql = _secure_invitations_sql()
    compact = _compact(sql)

    assert (
        "requested_by uuid references auth.users(id) on delete set null"
        in compact
    )
    assert "requested_by_audit_id uuid not null" in compact
    assert (
        "invited_user_id uuid references auth.users(id) on delete set null"
        in compact
    )
    assert "invited_user_audit_id uuid" in compact
    assert "foreign key (invited_by) references auth.users(id) on delete set null" in (
        compact
    )
    assert "invited_by_audit_id uuid" in compact


def test_cancel_and_revoke_close_finalized_invited_membership():
    sql = _secure_invitations_sql()
    compact = _compact(sql)
    cancel_start = compact.index(
        "create or replace function private.cancel_member_invitation"
    )
    cancel_end = compact.index("$$;", cancel_start) + 3
    cancel = compact[cancel_start:cancel_end]
    revoke_start = compact.index(
        "create or replace function private.revoke_member"
    )
    revoke_end = compact.index("$$;", revoke_start) + 3
    revoke = compact[revoke_start:revoke_end]

    assert "target_request.status = 'finalized'" in cancel
    assert "membership_status = 'active'" in cancel
    assert "active membership requires revoke_member" in cancel
    assert "set status = 'revoked'" in cancel
    assert "devices.status = 'pending'" in cancel
    assert "set status = 'cancelled'" in cancel
    assert "target_invitation_id" in revoke
    assert "target_status = 'invited'" in revoke
    assert "private.member_invitation_requests" in revoke
    assert "set status = 'cancelled'" in revoke
    assert "r.requested_by_audit_id = target_user_id" in revoke
    assert "r.status = 'requested'" in revoke


def test_invitation_management_list_is_bounded_and_admin_only():
    sql = _secure_invitations_sql()
    compact = _compact(sql)
    private_start = compact.index(
        "create or replace function private.list_member_invitations"
    )
    private_end = compact.index("$$;", private_start) + 3
    private_block = compact[private_start:private_end]
    public_start = compact.index(
        "create or replace function public.list_member_invitations"
    )
    public_end = compact.index("$$;", public_start) + 3
    public_block = compact[public_start:public_end]

    assert "m.status = 'active'" in private_block
    assert "actor_role not in ('owner','admin')" in private_block
    assert "limit 200" in private_block
    assert "email_sha256" not in private_block
    assert "requested_by" not in private_block
    assert "invited_user" not in private_block
    assert "security definer set search_path = ''" in private_block
    assert "security invoker set search_path = ''" in public_block
    assert (
        "select * from private.list_member_invitations(p_organization_id)"
        in public_block
    )
    assert (
        "revoke all on function private.list_member_invitations(uuid) "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "grant execute on function public.list_member_invitations(uuid) "
        "to authenticated"
    ) in compact


def test_invitation_foreign_keys_have_covering_indexes():
    sql = (
        MIGRATIONS / "202607300017_v9_invitation_fk_indexes.sql"
    ).read_text(encoding="utf-8").lower()
    compact = _compact(sql)

    assert compact.startswith("-- cover invitation lifecycle foreign keys")
    assert "begin;" in compact
    assert compact.endswith("commit;")
    for fragment in (
        "on private.member_invitation_requests(requested_by)",
        "on private.member_invitation_requests(invited_user_id)",
        "on public.memberships(invited_by)",
        "on public.memberships(organization_id,invitation_request_id)",
    ):
        assert fragment in compact
