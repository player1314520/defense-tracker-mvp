#!/bin/sh
set -eu
umask 077

config_file=${MVP_PRODUCTION_ENV:-/etc/defense-tracker/production.env}
[ -f "$config_file" ] || {
    printf '%s\n' "retention configuration is missing" >&2
    exit 64
}
set -a
# shellcheck disable=SC1090
. "$config_file"
set +a

for command_name in curl python3; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf '%s\n' "required retention command is missing: $command_name" >&2
        exit 69
    }
done

: "${API_DOMAIN:?API_DOMAIN is required}"
: "${SUPABASE_STACK_DIR:?SUPABASE_STACK_DIR is required}"
official_env="$SUPABASE_STACK_DIR/.env"
[ -r "$official_env" ] || {
    printf '%s\n' "protected Supabase environment is unreadable" >&2
    exit 77
}

secret_key=$(python3 - "$official_env" <<'PY'
import pathlib
import sys

matches = []
for raw in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    name, value = line.split("=", 1)
    if name.strip() != "SUPABASE_SECRET_KEY":
        continue
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    matches.append(value)
if len(matches) != 1 or not matches[0].startswith("sb_secret_"):
    raise SystemExit("SUPABASE_SECRET_KEY must be defined exactly once")
print(matches[0], end="")
PY
)

response_file=$(mktemp)
header_file=$(mktemp)
trap 'rm -f -- "$response_file" "$header_file"' EXIT HUP INT TERM
printf '%s\n' \
    "apikey: $secret_key" \
    "Authorization: Bearer $secret_key" \
    'Content-Type: application/json' > "$header_file"
unset secret_key
status=$(curl --silent --show-error \
    --output "$response_file" \
    --write-out '%{http_code}' \
    --request POST \
    "https://$API_DOMAIN/rest/v1/rpc/purge_expired_access_application_data" \
    --header "@$header_file" \
    --data '{}')
[ "$status" = 200 ] || {
    printf '%s\n' "retention RPC failed with HTTP $status" >&2
    exit 75
}

python3 - "$response_file" <<'PY'
import json
import pathlib
import sys

expected = {
    "expired_invitations",
    "expired_memberships",
    "stale_approvals",
    "pending_deleted",
    "contacts_purged",
    "invitation_contacts_purged",
    "audit_deleted",
    "invitation_audit_deleted",
    "applications_deleted",
    "rate_buckets_deleted",
    "event_usage_deleted",
}
payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(payload, dict) or set(payload) != expected:
    raise SystemExit("retention RPC returned an unexpected shape")
if any(not isinstance(value, int) or value < 0 for value in payload.values()):
    raise SystemExit("retention RPC returned an invalid count")
print("[RETENTION] " + " ".join(f"{key}={payload[key]}" for key in sorted(expected)))
PY
