# -*- coding: utf-8 -*-
"""Static contract for bounded, structurally valid sync ciphertext rows."""

import re
from pathlib import Path


MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "supabase"
    / "migrations"
    / "202607300019_v9_sync_ciphertext_constraints.sql"
)
PUSH_IDEMPOTENCY_MIGRATION = (
    MIGRATION.parent / "202607260009_v9_push_idempotency.sql"
)
OUTER_KEYS = (
    "event_id",
    "organization_id",
    "record_id",
    "operation",
    "payload",
)
PAYLOAD_REQUIRED_KEYS = (
    "organization_id",
    "record_id",
    "record_type",
    "version",
    "version_id",
    "base_version_id",
    "key_version",
    "ciphertext",
    "nonce",
    "wrapped_data_key",
    "wrap_nonce",
    "content_hash",
    "device_id",
    "deleted",
)
RECORD_TYPES = (
    "source",
    "evidence",
    "claim",
    "entity",
    "relation",
    "geo_event",
    "alert_rule",
    "alert",
    "case",
    "job",
    "scenario",
    "document",
    "publication_item",
    "audit_event",
)


def _compact() -> str:
    return " ".join(MIGRATION.read_text(encoding="utf-8").lower().split())


def _source() -> str:
    return MIGRATION.read_text(encoding="utf-8").lower()


def _function_from(source: str, schema: str, name: str) -> str:
    marker = f"create or replace function {schema}.{name}"
    assert marker in source
    start = source.index(marker)
    end = source.index("$$;", start) + 3
    return source[start:end]


def _function(schema: str, name: str) -> str:
    return _function_from(_source(), schema, name)


def _quoted_capture(source: str, pattern: str) -> tuple[str, ...]:
    match = re.search(pattern, source, flags=re.DOTALL)
    assert match is not None
    return tuple(re.findall(r"'([^']+)'", match.group(1)))


def test_record_versions_reject_malformed_aes_gcm_shapes():
    source = _compact()

    assert "octet_length(nonce) = 12" in source
    assert "octet_length(wrap_nonce) = 12" in source
    assert "octet_length(wrapped_data_key) = 48" in source
    assert (
        "octet_length(ciphertext) between 17 and 16777232"
        in source
    )


def test_private_validator_runs_before_push_cast_hash_decode_or_write():
    source = _source()
    compact = _compact()
    validator = _function("private", "validate_sync_ciphertext_event")
    push = _function("public", "push_record_event")
    push_compact = " ".join(push.split())
    validation_call = push_compact.index(
        "perform private.validate_sync_ciphertext_event(p_event)"
    )

    assert "returns void" in validator
    assert "set search_path = ''" in validator
    for unsafe in (
        "::uuid",
        "extensions.digest(",
        "private.decode_base64url(",
        "insert into public.record_heads",
        "update public.record_heads",
        "insert into public.record_versions",
        "insert into public.sync_events",
    ):
        assert validation_call < push_compact.index(unsafe)
    assert (
        "revoke all on function "
        "private.validate_sync_ciphertext_event(jsonb) "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "grant execute on function "
        "private.validate_sync_ciphertext_event"
    ) not in compact


def test_validator_enforces_exact_shape_types_ids_versions_and_record_types():
    validator = _function("private", "validate_sync_ciphertext_event")
    compact = " ".join(validator.split())

    assert "25165824" in validator
    assert "jsonb_typeof(p_event) <> 'object'" in compact
    assert "jsonb_typeof(payload) <> 'object'" in compact
    assert compact.count("jsonb_object_keys(") >= 2
    assert _quoted_capture(
        validator,
        r"p_event \?& array\[(.*?)\]::text\[\]",
    ) == OUTER_KEYS
    assert _quoted_capture(
        validator,
        r"payload \?& array\[(.*?)\]::text\[\]",
    ) == PAYLOAD_REQUIRED_KEYS
    assert _quoted_capture(
        validator,
        r"jsonb_object_keys\(p_event\).*?"
        r"where key_name not in \((.*?)\)\s*\)\s*then",
    ) == OUTER_KEYS
    assert _quoted_capture(
        validator,
        r"jsonb_object_keys\(payload\).*?"
        r"where key_name not in \((.*?)\)\s*\)\s*then",
    ) == PAYLOAD_REQUIRED_KEYS + ("updated_at",)
    assert "raise exception 'missing event field'" in validator
    assert "raise exception 'unsupported event field'" in validator
    assert "raise exception 'missing payload field'" in validator
    assert "raise exception 'unsupported payload field'" in validator
    for field, json_type in (
        ("event_id", "string"),
        ("organization_id", "string"),
        ("record_id", "string"),
        ("operation", "string"),
        ("payload", "object"),
    ):
        assert (
            f"jsonb_typeof(p_event->'{field}') <> '{json_type}'"
            in compact
        )
    for field, json_type in (
        ("organization_id", "string"),
        ("record_id", "string"),
        ("record_type", "string"),
        ("version", "number"),
        ("version_id", "string"),
        ("key_version", "number"),
        ("ciphertext", "string"),
        ("nonce", "string"),
        ("wrapped_data_key", "string"),
        ("wrap_nonce", "string"),
        ("content_hash", "string"),
        ("device_id", "string"),
        ("deleted", "boolean"),
    ):
        assert (
            f"jsonb_typeof(payload->'{field}') <> '{json_type}'"
            in compact
        )
    assert "jsonb_typeof(payload->'deleted') <> 'boolean'" in compact
    assert "jsonb_typeof(payload->'base_version_id') = 'null'" in compact
    assert "octet_length(payload->>'updated_at') > 64" in compact
    assert (
        "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
        "[0-9a-f]{4}-[0-9a-f]{12}$"
    ) in validator
    assert "9223372036854775807" in validator
    assert "2147483647" in validator
    assert _quoted_capture(
        validator,
        r"payload->>'record_type' not in \((.*?)\)\s*then",
    ) == RECORD_TYPES


def test_validator_requires_canonical_unpadded_base64url_and_decoded_sizes():
    validator = _function("private", "validate_sync_ciphertext_event")
    compact = " ".join(validator.split())

    assert "^[a-za-z0-9_-]+$" in validator
    assert "length(encoded_value) % 4 = 1" in compact
    for field in (
        "ciphertext",
        "nonce",
        "wrapped_data_key",
        "wrap_nonce",
    ):
        assert f"payload->>'{field}'" in validator
        assert f"private.decode_base64url(payload->>'{field}')" in compact
    assert compact.count("private.encode_base64url(") >= 4
    assert "octet_length(decoded_ciphertext) between 17 and 16777232" in compact
    assert "octet_length(decoded_nonce) = 12" in compact
    assert "octet_length(decoded_wrapped_data_key) = 48" in compact
    assert "octet_length(decoded_wrap_nonce) = 12" in compact


def test_validator_binds_upsert_and_delete_to_their_deleted_state():
    validator = _function("private", "validate_sync_ciphertext_event")
    compact = " ".join(validator.split())

    assert (
        "p_event->>'operation' = 'delete' "
        "and payload->>'deleted' <> 'true'"
    ) in compact
    assert (
        "p_event->>'operation' = 'upsert' "
        "and payload->>'deleted' <> 'false'"
    ) in compact
    assert "raise exception 'operation and deleted state mismatch'" in validator
    assert "p_event->>'operation' = 'snapshot'" not in validator


def test_push_replacement_preserves_009_idempotency_conflict_and_lock_semantics():
    source = _source()
    compact = _compact()
    push = _function("public", "push_record_event")
    push_compact = " ".join(push.split())
    original_push = _function_from(
        PUSH_IDEMPOTENCY_MIGRATION.read_text(encoding="utf-8").lower(),
        "public",
        "push_record_event",
    )
    push_without_validator = re.sub(
        r"\s*perform private\.validate_sync_ciphertext_event\(p_event\);",
        "",
        push,
        count=1,
    )

    assert " ".join(push_without_validator.split()) == " ".join(
        original_push.split()
    )
    assert "security definer" in push
    assert "set search_path = ''" in push
    assert "private.can_write_record(org_id,rec_type)" in push_compact
    assert "private.is_org_owner(org_id)" in push_compact
    assert "private.is_active_device_owner(org_id,dev_id)" in push_compact
    advisory = push_compact.index("pg_advisory_xact_lock")
    request_hash = push_compact.index(
        "canonical_request := jsonb_build_object"
    )
    duplicate = push_compact.index("from public.sync_events e")
    assert advisory < request_hash < duplicate
    assert "extensions.digest(" in push
    assert "existing_request_hash <> incoming_request_hash" in push_compact
    assert "raise exception 'event id payload mismatch'" in push
    assert "'applied',existing_applied" in push_compact
    assert "'head_version_id',current_head_id" in push_compact
    assert "from public.organizations o" in push_compact
    assert "for share" in push_compact
    assert "r.status = 'staging'" in push_compact
    assert "from public.record_heads h" in push_compact
    assert "for update" in push_compact
    assert "base_logical_version + 1 <> logical_ver" in push_compact
    assert "insert into public.conflicts" in push_compact
    assert "operation,applied,request_hash" in push_compact
    assert (
        "revoke all on function public.push_record_event(jsonb) "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "grant execute on function public.push_record_event(jsonb) "
        "to authenticated"
    ) in compact
    assert "drop function public.push_record_event" not in compact


def test_pull_replacement_keeps_membership_order_and_limits_encoded_page_budget():
    compact = _compact()
    pull = _function("public", "pull_sync_events")
    pull_compact = " ".join(pull.split())
    budget_guard = pull_compact.index(
        "if emitted_rows > 0 and cumulative_payload_bytes + "
        "payload_bytes > 33554432 then"
    )
    payload_assignment = pull_compact.index("payload := encoded_payload")
    byte_increment = pull_compact.index(
        "cumulative_payload_bytes := "
        "cumulative_payload_bytes + payload_bytes"
    )
    row_increment = pull_compact.index(
        "emitted_rows := emitted_rows + 1"
    )
    return_next = pull_compact.index("return next")

    assert "language plpgsql" in pull
    assert "stable" in pull
    assert "security definer" in pull
    assert "set search_path = ''" in pull
    assert "authentication required" in pull
    assert "from public.memberships m" in pull_compact
    assert "m.user_id = (select auth.uid())" in pull_compact
    assert "m.status = 'active'" in pull_compact
    assert (
        "e.cursor > greatest(coalesce(after_cursor,0),0)"
        in pull_compact
    )
    assert "order by e.cursor" in pull_compact
    assert (
        "least(greatest(coalesce(page_size,200),1),500)"
        in pull_compact
    )
    assert "private.encode_base64url" in pull
    assert (
        "payload_bytes := octet_length( "
        "convert_to(encoded_payload::text,'utf8') )"
    ) in pull_compact
    assert "33554432" in pull
    assert (
        "emitted_rows > 0 and cumulative_payload_bytes + "
        "payload_bytes > 33554432"
    ) in pull_compact
    assert (
        budget_guard
        < payload_assignment
        < byte_increment
        < row_increment
        < return_next
    )
    assert (
        "revoke all on function "
        "public.pull_sync_events(uuid,bigint,integer) "
        "from public, anon, authenticated"
    ) in compact
    assert (
        "grant execute on function "
        "public.pull_sync_events(uuid,bigint,integer) "
        "to authenticated"
    ) in compact


def test_ciphertext_constraints_are_transactional_and_do_not_touch_plaintext():
    source = _compact()

    assert source.startswith("--")
    assert "16 mib canonical json body" in source
    assert " begin; " in f" {source} "
    assert source.endswith("commit;")
    assert "record_versions" in source
    assert "plaintext" not in source
    for forbidden_key in (
        "'body'",
        "'content'",
        "'original_text'",
        "'report_body'",
    ):
        assert forbidden_key not in source
