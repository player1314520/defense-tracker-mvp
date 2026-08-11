#!/bin/sh
set -eu
umask 077

usage() {
    printf '%s\n' "usage: $0 OWNER_EMAIL_FILE [PRODUCTION_ENV]" >&2
    printf '%s\n' "       $0 --finalize OWNER_EMAIL_FILE OWNER_BOOTSTRAP_MANIFEST [PRODUCTION_ENV]" >&2
    exit 64
}

action=begin
if [ "${1:-}" = "--finalize" ]; then
    action=finalize
    shift
fi
if [ "$action" = begin ]; then
    [ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
    owner_email_file=$1
    owner_manifest_file=''
    config_file=${2:-/etc/defense-tracker/production.env}
else
    [ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage
    owner_email_file=$1
    owner_manifest_file=$2
    config_file=${3:-/etc/defense-tracker/production.env}
fi

assert_private_file() {
    protected_path=$1
    protected_label=$2
    [ -f "$protected_path" ] && [ -r "$protected_path" ] || {
        printf '%s\n' "$protected_label is missing or unreadable" >&2
        exit 66
    }
    protected_mode=$(stat -c '%a' "$protected_path")
    case "$protected_mode" in
        600|400) ;;
        *) printf '%s\n' "$protected_label must have mode 600 or 400" >&2; exit 77 ;;
    esac
}

assert_private_file "$owner_email_file" OWNER_EMAIL_FILE
[ "$action" = begin ] || assert_private_file "$owner_manifest_file" OWNER_BOOTSTRAP_MANIFEST
[ -f "$config_file" ] || { printf '%s\n' "production env file is missing" >&2; exit 66; }

set -a
# shellcheck disable=SC1090
. "$config_file"
set +a
: "${SUPABASE_STACK_DIR:?SUPABASE_STACK_DIR is required}"
: "${SUPABASE_OVERRIDE_FILE:?SUPABASE_OVERRIDE_FILE is required}"
: "${SUPABASE_KONG_LOOPBACK_PORT:?SUPABASE_KONG_LOOPBACK_PORT is required}"
: "${PORTAL_DOMAIN:?PORTAL_DOMAIN is required}"
: "${V9_AUTH_HOOK_ENABLED:?V9_AUTH_HOOK_ENABLED is required}"
: "${MVP_RELEASE_STATE_DIR:?MVP_RELEASE_STATE_DIR is required}"

for command_name in docker python3 stat flock mkdir chmod sleep; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf '%s\n' "required Owner bootstrap command is missing: $command_name" >&2
        exit 69
    }
done

base="$SUPABASE_STACK_DIR/docker-compose.yml"
upstream_env="$SUPABASE_STACK_DIR/.env"
[ -f "$base" ] && [ -f "$upstream_env" ] && [ -f "$SUPABASE_OVERRIDE_FILE" ] || {
    printf '%s\n' "pinned official Supabase stack is incomplete" >&2
    exit 66
}

case "$MVP_RELEASE_STATE_DIR" in
    /*) ;;
    *) printf '%s\n' "MVP_RELEASE_STATE_DIR must be absolute" >&2; exit 64 ;;
esac
mkdir -p "$MVP_RELEASE_STATE_DIR"
chmod 0700 "$MVP_RELEASE_STATE_DIR"
exec 9>"$MVP_RELEASE_STATE_DIR/.release.lock"
flock -n 9 || { printf '%s\n' "a release, rollback or backup is active" >&2; exit 75; }
exec 8>"$MVP_RELEASE_STATE_DIR/.supabase-app.lock"
flock -n 8 || { printf '%s\n' "a Supabase application install is active" >&2; exit 75; }

compose() {
    docker compose --env-file "$upstream_env" --file "$base" \
        --file "$SUPABASE_OVERRIDE_FILE" "$@"
}
psql_db() {
    compose exec -T db psql --username postgres --dbname postgres \
        --set ON_ERROR_STOP=1 "$@"
}

auth_contract=$(compose config --format json | python3 -c '
import json, sys
services = json.load(sys.stdin)["services"]
env = services["auth"]["environment"]
print(str(env.get("GOTRUE_DISABLE_SIGNUP", "")).lower() + ":" + str(env.get("GOTRUE_HOOK_BEFORE_USER_CREATED_ENABLED", "")).lower())
')
case "$auth_contract" in
    true:true|true:false) ;;
    *) printf '%s\n' "DISABLE_SIGNUP must be true and the Auth hook phase explicit" >&2; exit 65 ;;
esac

bootstrap_contract=$(psql_db --tuples-only --no-align --command \
    "select (to_regclass('private.mvp_owner_bootstrap') is not null and to_regprocedure('public.bootstrap_mvp_first_owner(uuid,text,uuid,text,text,uuid,text,text,text)') is not null)::text;")
[ "$bootstrap_contract" = true ] || {
    printf '%s\n' "Owner bootstrap migration/RPC is not installed" >&2
    exit 65
}

email_digest=$(python3 - "$owner_email_file" <<'PY'
import hashlib
import pathlib
import re
import sys

value = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip().lower()
pattern = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
if len(value) > 254 or len(value.split("@", 1)[0]) > 64 or not pattern.fullmatch(value):
    raise SystemExit("OWNER_EMAIL_FILE does not contain one valid normalized address")
print(hashlib.sha256(value.encode("utf-8")).hexdigest())
PY
)

marker=$(psql_db --tuples-only --no-align --command \
    "select email_sha256 || ':' || status || ':' || coalesce(auth_user_id::text,'') from private.mvp_owner_bootstrap where singleton;")

if [ "$action" = begin ]; then
    [ "$V9_AUTH_HOOK_ENABLED" = false ] || {
        printf '%s\n' "begin requires V9_AUTH_HOOK_ENABLED=false; public signup remains disabled" >&2
        exit 65
    }
    case "$marker" in
        "$email_digest:invited:"*|"$email_digest:provisioned:"*|"$email_digest:finalized:"*)
            printf '%s\n' "[BOOTSTRAP] Existing matching bootstrap is idempotent; no second invitation was sent."
            exit 0
            ;;
        ''|"$email_digest:preparing:"*|"$email_digest:failed:"*) ;;
        *) printf '%s\n' "bootstrap marker belongs to a different or ambiguous attempt" >&2; exit 65 ;;
    esac

    counts=$(psql_db --tuples-only --no-align --command \
        "select (select count(*) from auth.users) || ':' || (select count(*) from public.organizations) || ':' || (select count(*) from public.memberships) || ':' || (select count(*) from public.devices) || ':' || (select count(*) from private.device_sessions);")
    auth_count=${counts%%:*}
    tenant_counts=${counts#*:}
    [ "$tenant_counts" = "0:0:0:0" ] && [ "$auth_count" -le 1 ] || {
        printf '%s\n' "only an empty database can begin Owner bootstrap" >&2
        exit 65
    }
    if [ -z "$marker" ]; then
        [ "$auth_count" = 0 ] || {
            printf '%s\n' "only an empty database can begin Owner bootstrap" >&2
            exit 65
        }
        psql_db --quiet --set "email_digest=$email_digest" <<'SQL'
insert into private.mvp_owner_bootstrap(singleton,email_sha256,status)
values (true, :'email_digest', 'preparing');
SQL
    fi

    matching_user=$(psql_db --tuples-only --no-align --set "email_digest=$email_digest" --command \
        "select coalesce(min(id)::text,'') from auth.users where encode(extensions.digest(pg_catalog.convert_to(pg_catalog.lower(pg_catalog.btrim(email)),'UTF8'),'sha256'),'hex') = :'email_digest';")
    if [ "$auth_count" = 1 ] && [ -z "$matching_user" ]; then
        printf '%s\n' "the only Auth identity does not match the bootstrap marker" >&2
        exit 65
    fi
    if [ -z "$matching_user" ]; then
        if ! python3 - "$owner_email_file" "$config_file" "$upstream_env" <<'PY'
import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

def load_env(path):
    values = {}
    for raw in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values

email_value = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip().lower()
production = load_env(sys.argv[2])
upstream = load_env(sys.argv[3])
service_key = upstream.get("SERVICE_ROLE_KEY", "")
if not service_key:
    raise SystemExit(65)
redirect = f"https://{production['PORTAL_DOMAIN']}/portal/"
url = (
    f"http://127.0.0.1:{production['SUPABASE_KONG_LOOPBACK_PORT']}/auth/v1/invite?"
    + urllib.parse.urlencode({"redirect_to": redirect})
)
request = urllib.request.Request(
    url,
    data=json.dumps({"email": email_value}, separators=(",", ":")).encode("utf-8"),
    headers={
        "apikey": service_key,
        "Authorization": f"Bearer {service_key}",
        "Content-Type": "application/json",
        "User-Agent": "DefenseTracker-Owner-Bootstrap/1",
    },
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status not in (200, 201):
            raise SystemExit(70)
        response.read(1024 * 1024)
except (urllib.error.URLError, OSError, TimeoutError):
    raise SystemExit(70)
PY
        then
            psql_db --quiet --set "email_digest=$email_digest" --command \
                "update private.mvp_owner_bootstrap set status='failed',updated_at=timezone('utc',now()) where singleton and email_sha256=:'email_digest' and status in ('preparing','failed');" || true
        fi

        attempt=0
        while [ "$attempt" -lt 10 ]; do
            matching_user=$(psql_db --tuples-only --no-align --set "email_digest=$email_digest" --command \
                "select coalesce(min(id)::text,'') from auth.users where encode(extensions.digest(pg_catalog.convert_to(pg_catalog.lower(pg_catalog.btrim(email)),'UTF8'),'sha256'),'hex') = :'email_digest';")
            [ -z "$matching_user" ] || break
            attempt=$((attempt + 1))
            sleep 1
        done
    fi

    [ -n "$matching_user" ] || {
        printf '%s\n' "Owner invitation did not create a verifiable Auth record" >&2
        exit 70
    }
    total_auth=$(psql_db --tuples-only --no-align --command "select count(*) from auth.users;")
    [ "$total_auth" = 1 ] || { printf '%s\n' "Owner bootstrap Auth state is not unique" >&2; exit 65; }
    psql_db --quiet --set "email_digest=$email_digest" --set "auth_user_id=$matching_user" <<'SQL'
update private.mvp_owner_bootstrap
   set status='invited',auth_user_id=:'auth_user_id'::uuid,
       updated_at=timezone('utc',now())
 where singleton and email_sha256=:'email_digest'
   and status in ('preparing','failed');
SQL
    printf '%s\n' "[BOOTSTRAP] First Owner invitation registered without logging its address."
    printf '%s\n' "[BOOTSTRAP] Complete verified desktop login, export the protected manifest, enable the Auth hook, then run --finalize."
    exit 0
fi

[ "$V9_AUTH_HOOK_ENABLED" = true ] || {
    printf '%s\n' "--finalize requires V9_AUTH_HOOK_ENABLED=true in the protected production env" >&2
    exit 65
}
case "$marker" in
    "$email_digest:invited:"*|"$email_digest:provisioned:"*|"$email_digest:finalized:"*) ;;
    *) printf '%s\n' "matching invited/provisioned bootstrap marker is required" >&2; exit 65 ;;
esac
auth_user_id=${marker##*:}
[ -n "$auth_user_id" ] || { printf '%s\n' "bootstrap Auth identity is missing" >&2; exit 65; }

if ! python3 - "$owner_manifest_file" "$config_file" "$upstream_env" "$auth_user_id" <<'PY'
import base64
import hmac
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request
import uuid

EXPECTED_FIELDS = {
    "schema_version",
    "organization_id",
    "owner_user_id",
    "session_id",
    "name_ciphertext",
    "name_nonce",
    "device_id",
    "device_public_key",
    "device_name_ciphertext",
    "device_name_nonce",
    "key_algorithm",
    "device_kind",
}

def load_env(path):
    values = {}
    for raw in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values

def canonical_uuid(value, label):
    if not isinstance(value, str):
        raise ValueError(label)
    parsed = uuid.UUID(value)
    if str(parsed) != value:
        raise ValueError(label)
    return value

def canonical_base64url(value, label, minimum, maximum):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError(label)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if not minimum <= len(raw) <= maximum:
        raise ValueError(label)
    canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if not hmac.compare_digest(value, canonical):
        raise ValueError(label)
    return raw

try:
    manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != EXPECTED_FIELDS:
        raise ValueError("manifest fields")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("schema version")
    if manifest["key_algorithm"] != "p256" or manifest["device_kind"] != "desktop":
        raise ValueError("fixed device contract")
    owner_id = canonical_uuid(manifest["owner_user_id"], "owner id")
    if not hmac.compare_digest(owner_id, sys.argv[4]):
        raise ValueError("owner identity")
    organization_id = canonical_uuid(manifest["organization_id"], "organization id")
    device_id = canonical_uuid(manifest["device_id"], "device id")
    session_id = manifest["session_id"]
    if (
        not isinstance(session_id, str)
        or not 16 <= len(session_id) <= 256
        or re.fullmatch(r"[A-Za-z0-9._~-]+", session_id) is None
    ):
        raise ValueError("session id")
    canonical_base64url(manifest["name_ciphertext"], "organization name", 16, 1024)
    canonical_base64url(manifest["name_nonce"], "organization nonce", 12, 12)
    public_key = canonical_base64url(manifest["device_public_key"], "device key", 65, 65)
    if public_key[0] != 4:
        raise ValueError("device key")
    canonical_base64url(manifest["device_name_ciphertext"], "device name", 16, 1024)
    canonical_base64url(manifest["device_name_nonce"], "device nonce", 12, 12)
except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
    raise SystemExit(65)

production = load_env(sys.argv[2])
upstream = load_env(sys.argv[3])
service_key = upstream.get("SERVICE_ROLE_KEY", "")
if not service_key:
    raise SystemExit(65)
payload = {
    "p_owner_user_id": owner_id,
    "p_session_id": session_id,
    "p_organization_id": organization_id,
    "p_name_ciphertext": manifest["name_ciphertext"],
    "p_name_nonce": manifest["name_nonce"],
    "p_device_id": device_id,
    "p_device_public_key": manifest["device_public_key"],
    "p_device_name_ciphertext": manifest["device_name_ciphertext"],
    "p_device_name_nonce": manifest["device_name_nonce"],
}
url = (
    f"http://127.0.0.1:{production['SUPABASE_KONG_LOOPBACK_PORT']}"
    "/rest/v1/rpc/bootstrap_mvp_first_owner"
)
request = urllib.request.Request(
    url,
    data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    headers={
        "apikey": service_key,
        "Authorization": f"Bearer {service_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "DefenseTracker-Owner-Bootstrap/1",
    },
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise SystemExit(70)
        raw = response.read(1024 * 1024 + 1)
except (urllib.error.URLError, OSError, TimeoutError):
    raise SystemExit(70)
if len(raw) > 1024 * 1024:
    raise SystemExit(70)
try:
    result = json.loads(raw)
except (UnicodeError, json.JSONDecodeError):
    raise SystemExit(70)
if (
    not isinstance(result, dict)
    or result.get("status") != "provisioned"
    or result.get("organization_id") != organization_id
    or result.get("device_id") != device_id
):
    raise SystemExit(70)
PY
then
    printf '%s\n' "service-only Owner bootstrap RPC failed; no payload or credential was logged" >&2
    exit 70
fi

state=$(psql_db --tuples-only --no-align --set "auth_user_id=$auth_user_id" --command \
    "select (select count(*) from auth.users) || ':' || (select count(*) from public.organizations) || ':' || (select count(*) from public.memberships where user_id=:'auth_user_id'::uuid and status='active' and role='owner') || ':' || (select count(*) from public.devices where user_id=:'auth_user_id'::uuid and status='active' and key_algorithm='p256' and device_kind='desktop') || ':' || (select count(*) from private.device_sessions where user_id=:'auth_user_id'::uuid and status='active') || ':' || (select status from private.mvp_owner_bootstrap where singleton);")
case "$state" in
    1:1:1:1:1:provisioned|1:1:1:1:1:finalized) ;;
    *) printf '%s\n' "atomic Owner organization/device/session state is not unique" >&2; exit 65 ;;
esac

compose up --detach --no-deps --force-recreate --wait --wait-timeout 180 auth
compose exec -T auth /bin/sh -eu -c '[ "$GOTRUE_DISABLE_SIGNUP" = true ] && [ "$GOTRUE_HOOK_BEFORE_USER_CREATED_ENABLED" = true ]'
psql_db --quiet --set "email_digest=$email_digest" --set "auth_user_id=$auth_user_id" <<'SQL'
update private.mvp_owner_bootstrap
   set status='finalized',updated_at=timezone('utc',now()),
       finalized_at=coalesce(finalized_at,timezone('utc',now()))
 where singleton and email_sha256=:'email_digest'
   and auth_user_id=:'auth_user_id'::uuid
   and status in ('provisioned','finalized');
SQL
final_status=$(psql_db --tuples-only --no-align --set "email_digest=$email_digest" --command \
    "select status from private.mvp_owner_bootstrap where singleton and email_sha256=:'email_digest';")
[ "$final_status" = finalized ] || {
    printf '%s\n' "Owner bootstrap finalization marker was not committed" >&2
    exit 65
}
printf '%s\n' "[BOOTSTRAP] First Owner, organization and active desktop session are provisioned; invite-only Auth hook is active."
