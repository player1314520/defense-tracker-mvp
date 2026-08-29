#!/bin/sh
set -eu

config_file=${1:-/etc/defense-tracker/production.env}
[ -f "$config_file" ] || { printf '%s\n' "production env file is missing" >&2; exit 64; }

set -a
# shellcheck disable=SC1090
. "$config_file"
set +a

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf '%s\n' "required preinstalled command is missing: $1" >&2
        exit 69
    }
}

for command_name in docker python3 curl age rclone flock tar sha256sum grep git stat sed systemctl; do
    require_command "$command_name"
done
python3 - <<'PY'
import sys

if sys.version_info < (3, 11):
    raise SystemExit("Python >= 3.11 is required")
PY
docker compose version >/dev/null 2>&1 || {
    printf '%s\n' "Docker Compose v2 is required" >&2
    exit 69
}
compose_version=$(docker compose version --short | sed 's/^v//; s/[^0-9.].*$//')
python3 - "$compose_version" <<'PY'
import sys

def parts(value):
    try:
        return tuple(int(item) for item in value.split("."))
    except ValueError as exc:
        raise SystemExit("unable to parse Docker Compose version") from exc

if parts(sys.argv[1]) < (2, 24, 4):
    raise SystemExit("Docker Compose >= 2.24.4 is required for !override")
PY

required_names='PORTAL_DOMAIN API_DOMAIN ACME_EMAIL PORTAL_IMAGE CADDY_IMAGE MVP_SECRETS_DIR MVP_RELEASE_STATE_DIR SUPABASE_STACK_DIR SUPABASE_UPSTREAM_SHA SUPABASE_OVERRIDE_FILE SUPABASE_FUNCTIONS_DEPLOY_DIR SUPABASE_POSTGRES_DATA_DIR SUPABASE_STORAGE_DATA_DIR SUPABASE_CONFIG_DIR MVP_CONFIG_DIR BACKUP_STAGING_DIR BACKUP_REMOTE AGE_RECIPIENT_FILE RCLONE_CONFIG V9_AUTH_HOOK_ENABLED ACCESS_APPLICATIONS_ENABLED MVP_EXTERNAL_WAF_ENABLED MVP_WAF_REALTIME_WEBSOCKET_ALLOWED WAF_TRUSTED_PROXY_CIDRS'
for variable_name in $required_names; do
    eval "variable_value=\${$variable_name:-}"
    [ -n "$variable_value" ] || {
        printf '%s\n' "required setting is empty: $variable_name" >&2
        exit 64
    }
done

[ "$MVP_EXTERNAL_WAF_ENABLED" = true ] || {
    printf '%s\n' "production configuration must require upstream connection and burst protection" >&2
    exit 64
}
[ "$MVP_WAF_REALTIME_WEBSOCKET_ALLOWED" = true ] || {
    printf '%s\n' "production WAF must allow the Realtime WebSocket route" >&2
    exit 64
}
for timer_name in defense-tracker-backup.timer defense-tracker-retention.timer; do
    systemctl is-enabled --quiet "$timer_name" || {
        printf '%s\n' "required systemd timer is not enabled: $timer_name" >&2
        exit 65
    }
    systemctl is-active --quiet "$timer_name" || {
        printf '%s\n' "required systemd timer is not active: $timer_name" >&2
        exit 65
    }
done
case "$ACCESS_APPLICATIONS_ENABLED" in
    true|false) ;;
    *) printf '%s\n' "ACCESS_APPLICATIONS_ENABLED must be true or false" >&2; exit 64 ;;
esac

python3 - "$PORTAL_DOMAIN" "$API_DOMAIN" "$WAF_TRUSTED_PROXY_CIDRS" <<'PY'
import ipaddress
import re
import sys

domain_pattern = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
portal, api, raw_waf_cidrs = sys.argv[1:]
for label, value in (("PORTAL_DOMAIN", portal), ("API_DOMAIN", api)):
    if (
        not value.isascii()
        or value != value.lower()
        or value.endswith(".invalid")
        or domain_pattern.fullmatch(value) is None
    ):
        raise SystemExit(f"{label} is not one exact lowercase production hostname")
if portal == api:
    raise SystemExit("portal and API domains must differ")
waf_cidrs = raw_waf_cidrs.split()
if not waf_cidrs:
    raise SystemExit("WAF_TRUSTED_PROXY_CIDRS requires reviewed public CIDRs")
for raw_cidr in waf_cidrs:
    try:
        network = ipaddress.ip_network(raw_cidr, strict=True)
    except ValueError as exc:
        raise SystemExit("WAF_TRUSTED_PROXY_CIDRS contains an invalid CIDR") from exc
    if (
        network.is_private
        or network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.is_reserved
        or network.is_unspecified
    ):
        raise SystemExit("WAF_TRUSTED_PROXY_CIDRS must contain public provider ranges only")
PY

printf '%s' "$PORTAL_IMAGE" | grep -Eq '^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$' || {
    printf '%s\n' "PORTAL_IMAGE must be pinned by an approved repository digest" >&2
    exit 64
}
printf '%s' "$CADDY_IMAGE" | grep -Eq '@sha256:[0-9a-f]{64}$' || {
    printf '%s\n' "CADDY_IMAGE must be pinned by sha256 digest" >&2
    exit 64
}

secret_key="$MVP_SECRETS_DIR/supabase_publishable_key"
for protected_file in "$config_file" "$secret_key" "$AGE_RECIPIENT_FILE" "$RCLONE_CONFIG"; do
    [ -f "$protected_file" ] || { printf '%s\n' "required protected file is missing" >&2; exit 66; }
    mode=$(stat -c '%a' "$protected_file")
    case "$mode" in
        600|400) ;;
        *) printf '%s\n' "protected files must have mode 600 or 400" >&2; exit 77 ;;
    esac
done

for persistent_path in "$SUPABASE_POSTGRES_DATA_DIR" "$SUPABASE_STORAGE_DATA_DIR" "$SUPABASE_CONFIG_DIR" "$SUPABASE_FUNCTIONS_DEPLOY_DIR" "$MVP_CONFIG_DIR" "$BACKUP_STAGING_DIR"; do
    case "$persistent_path" in /*) ;; *) printf '%s\n' "persistent paths must be absolute" >&2; exit 64 ;; esac
    [ -d "$persistent_path" ] || { printf '%s\n' "required persistent directory is missing" >&2; exit 66; }
done
[ "$SUPABASE_POSTGRES_DATA_DIR" != "$SUPABASE_STORAGE_DATA_DIR" ] || {
    printf '%s\n' "Postgres and Storage must use different persistent paths" >&2
    exit 64
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
expected_release_sha=${MVP_EXPECTED_RELEASE_SHA:-$(git -C "$project_root" rev-parse HEAD 2>/dev/null || true)}
printf '%s' "$expected_release_sha" | grep -Eq '^[0-9a-f]{40}$' || {
    printf '%s\n' "MVP_EXPECTED_RELEASE_SHA must be a full Git commit SHA" >&2
    exit 64
}
[ "$(git -C "$project_root" rev-parse HEAD 2>/dev/null || true)" = "$expected_release_sha" ] || {
    printf '%s\n' "project checkout HEAD does not match the expected release SHA" >&2
    exit 65
}
[ -z "$(git -C "$project_root" status --porcelain --untracked-files=all)" ] || {
    printf '%s\n' "project checkout must be clean during preflight" >&2
    exit 65
}
compose_file="$script_dir/../docker-compose.production.yml"
docker compose --env-file "$config_file" --file "$compose_file" config --quiet

supabase_compose="$SUPABASE_STACK_DIR/docker-compose.yml"
supabase_env="$SUPABASE_STACK_DIR/.env"
[ -f "$supabase_compose" ] && [ -f "$supabase_env" ] && [ -f "$SUPABASE_OVERRIDE_FILE" ] || {
    printf '%s\n' "pinned official Supabase Compose checkout is incomplete" >&2
    exit 66
}
mode=$(stat -c '%a' "$supabase_env")
case "$mode" in
    600|400) ;;
    *) printf '%s\n' "official Supabase .env must have mode 600 or 400" >&2; exit 77 ;;
esac
[ -L "$SUPABASE_FUNCTIONS_DEPLOY_DIR" ] || {
    printf '%s\n' "SUPABASE_FUNCTIONS_DEPLOY_DIR must be the installer-managed current symlink" >&2
    exit 65
}
printf '%s' "$SUPABASE_UPSTREAM_SHA" | grep -Eq '^[0-9a-f]{40}$' || {
    printf '%s\n' "SUPABASE_UPSTREAM_SHA must be a full Git commit SHA" >&2
    exit 64
}
actual_supabase_sha=$(git -C "$SUPABASE_STACK_DIR" rev-parse HEAD 2>/dev/null || true)
[ "$actual_supabase_sha" = "$SUPABASE_UPSTREAM_SHA" ] || {
    printf '%s\n' "official Supabase checkout does not match the approved commit" >&2
    exit 65
}
[ -z "$(git -C "$SUPABASE_STACK_DIR" status --porcelain --untracked-files=all)" ] || {
    printf '%s\n' "official Supabase checkout must be clean" >&2
    exit 65
}
supabase_json=$(docker compose --env-file "$supabase_env" --file "$supabase_compose" \
    --file "$SUPABASE_OVERRIDE_FILE" config --format json)
export PORTAL_PUBLISHABLE_KEY_FILE="$secret_key"
export OFFICIAL_SUPABASE_ENV_FILE="$supabase_env"
printf '%s' "$supabase_json" | python3 -c '
import base64, hmac, json, os, pathlib, re, sys
data = json.load(sys.stdin)
services = data.get("services", {})
if not {"db", "storage", "kong", "auth", "functions", "realtime"}.issubset(services):
    raise SystemExit("official Supabase services db/storage/kong/auth/functions/realtime are required")
for service_name, service in services.items():
    for port in service.get("ports") or []:
        if port.get("published") and port.get("host_ip") not in {"127.0.0.1", "::1"}:
            raise SystemExit(f"Supabase service publishes a non-loopback port: {service_name}")
kong_ports = services["kong"].get("ports") or []
if len(kong_ports) != 1 or kong_ports[0].get("target") != 8000 or kong_ports[0].get("host_ip") != "127.0.0.1":
    raise SystemExit("Kong must publish only HTTP target 8000 on 127.0.0.1")
if services.get("supavisor", {}).get("ports"):
    raise SystemExit("Supavisor/Postgres ports must not be published")
def assert_bind(service_name, target, expected_env):
    mounts = services[service_name].get("volumes") or []
    sources = [m.get("source") for m in mounts if m.get("target") == target]
    if len(sources) != 1 or not sources[0]:
        raise SystemExit(f"{service_name} must have one explicit persistent mount at {target}")
    actual = pathlib.Path(sources[0]).resolve()
    expected = pathlib.Path(os.environ[expected_env]).resolve()
    if actual != expected:
        raise SystemExit(f"{service_name} persistent mount differs from {expected_env}")
    if service_name == "functions":
        matching = [m for m in mounts if m.get("target") == target]
        if matching[0].get("read_only") is not True:
            raise SystemExit("deployed Edge Functions must be mounted read-only")
assert_bind("db", "/var/lib/postgresql/data", "SUPABASE_POSTGRES_DATA_DIR")
assert_bind("storage", "/var/lib/storage", "SUPABASE_STORAGE_DATA_DIR")
assert_bind("functions", "/home/deno/functions", "SUPABASE_FUNCTIONS_DEPLOY_DIR")

portal_key = pathlib.Path(os.environ["PORTAL_PUBLISHABLE_KEY_FILE"]).read_text(encoding="ascii").strip()
if not portal_key.startswith("sb_publishable_"):
    raise SystemExit("Portal publishable key format is invalid")

def exact_dotenv_value(name):
    matches = []
    path = pathlib.Path(os.environ["OFFICIAL_SUPABASE_ENV_FILE"])
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() != name:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"\x27":
            value = value[1:-1]
        matches.append(value)
    if len(matches) != 1:
        raise SystemExit(f"official Supabase .env must define {name} exactly once")
    return matches[0]

official_key = exact_dotenv_value("SUPABASE_PUBLISHABLE_KEY")
if not re.fullmatch(r"sb_publishable_[A-Za-z0-9_-]+", official_key):
    raise SystemExit("official Supabase publishable key format is invalid")
try:
    official_keys = json.loads(exact_dotenv_value("SUPABASE_PUBLISHABLE_KEYS"))
except (TypeError, json.JSONDecodeError):
    raise SystemExit("official Supabase publishable key map is invalid")
if not isinstance(official_keys, dict) or not hmac.compare_digest(
    str(official_keys.get("default", "")), official_key
):
    raise SystemExit("official Supabase publishable key map differs from its primary key")
kong_key = str(services["kong"].get("environment", {}).get("SUPABASE_PUBLISHABLE_KEY", ""))
function_keys = services["functions"].get("environment", {}).get("SUPABASE_PUBLISHABLE_KEYS", "")
try:
    function_key = json.loads(function_keys).get("default", "")
except (TypeError, json.JSONDecodeError):
    raise SystemExit("Functions publishable key map is invalid")
if (
    not hmac.compare_digest(portal_key, official_key)
    or not hmac.compare_digest(portal_key, kong_key)
    or not hmac.compare_digest(portal_key, function_key)
):
    raise SystemExit("Portal and official Supabase publishable keys differ")

auth_env = services["auth"].get("environment", {})
expected_api = "https://" + os.environ["API_DOMAIN"] + "/auth/v1"
if auth_env.get("API_EXTERNAL_URL") != expected_api:
    raise SystemExit("API_EXTERNAL_URL must be the exact public /auth/v1 URL")
if str(auth_env.get("GOTRUE_DISABLE_SIGNUP", "")).lower() != "true":
    raise SystemExit("public Auth signup must remain disabled")
expected_redirects = ["https://" + os.environ["PORTAL_DOMAIN"] + "/portal/"] + [
    f"http://127.0.0.1:{port}/api/v9/auth/callback"
    for port in range(49231, 49236)
]
actual_redirects = [
    item.strip()
    for item in exact_dotenv_value("ADDITIONAL_REDIRECT_URLS").split(",")
    if item.strip()
]
if actual_redirects != expected_redirects:
    raise SystemExit("Auth redirect allowlist must contain only Portal and five desktop PKCE callbacks")
if str(auth_env.get("GOTRUE_HOOK_BEFORE_USER_CREATED_ENABLED", "")).lower() != os.environ["V9_AUTH_HOOK_ENABLED"].lower():
    raise SystemExit("Auth hook phase differs from production configuration")

function_env = services["functions"].get("environment", {})
if str(function_env.get("VERIFY_JWT", "")).lower() != "false":
    raise SystemExit("FUNCTIONS_VERIFY_JWT must be false for anonymous access applications")
if exact_dotenv_value("FUNCTIONS_VERIFY_JWT").lower() != "false":
    raise SystemExit("official Supabase .env must keep FUNCTIONS_VERIFY_JWT=false")
runtime_service_role = str(function_env.get("SUPABASE_SERVICE_ROLE_KEY", ""))
official_service_role = exact_dotenv_value("SERVICE_ROLE_KEY")
if not official_service_role or not hmac.compare_digest(runtime_service_role, official_service_role):
    raise SystemExit("Functions service-role credential is missing")
origin = "https://" + os.environ["PORTAL_DOMAIN"]
if function_env.get("V9_ALLOWED_ORIGINS") != origin:
    raise SystemExit("Edge Function origin must be the exact Portal origin")
if str(function_env.get("V9_ACCESS_APPLICATIONS_ENABLED", "")).lower() != os.environ["ACCESS_APPLICATIONS_ENABLED"].lower():
    raise SystemExit("Portal and Edge Function application gates differ")
if function_env.get("V9_INVITE_REDIRECT_URL") != origin + "/portal/":
    raise SystemExit("invite redirect must be the exact Portal URL")

def decode_canonical_32(name):
    value = str(function_env.get(name, ""))
    if not value or "=" in value:
        raise SystemExit(f"{name} must be unpadded canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        raise SystemExit(f"{name} is not valid base64url")
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if len(decoded) != 32 or not hmac.compare_digest(value, canonical):
        raise SystemExit(f"{name} must encode exactly 32 bytes")
    return value
hmac_key = decode_canonical_32("ACCESS_APPLICATION_HMAC_KEY")
encryption_key = decode_canonical_32("ACCESS_APPLICATION_ENCRYPTION_KEY")
if not hmac.compare_digest(hmac_key, exact_dotenv_value("ACCESS_APPLICATION_HMAC_KEY")):
    raise SystemExit("runtime HMAC key differs from the official Supabase .env")
if not hmac.compare_digest(
    encryption_key, exact_dotenv_value("ACCESS_APPLICATION_ENCRYPTION_KEY")
):
    raise SystemExit("runtime encryption key differs from the official Supabase .env")
if hmac.compare_digest(hmac_key, encryption_key):
    raise SystemExit("access application keys must be independent")
try:
    key_version = int(function_env.get("ACCESS_APPLICATION_ENCRYPTION_KEY_VERSION", ""))
except (TypeError, ValueError):
    raise SystemExit("access application key version is invalid")
if not 1 <= key_version <= 100:
    raise SystemExit("access application key version must be 1..100")
if str(key_version) != exact_dotenv_value("ACCESS_APPLICATION_ENCRYPTION_KEY_VERSION"):
    raise SystemExit("runtime encryption key version differs from the official Supabase .env")
if str(services["storage"].get("environment", {}).get("FILE_SIZE_LIMIT", "")) != "16777232":
    raise SystemExit("Storage limit must be 16 MiB plus one AES-GCM tag")
'

compose_services=$(docker compose --env-file "$supabase_env" --file "$supabase_compose" \
    --file "$SUPABASE_OVERRIDE_FILE" ps --status running --services 2>/dev/null || true)
if printf '%s\n' "$compose_services" | grep -qx db; then
    "$script_dir/verify-supabase-app.sh" "$expected_release_sha" "$config_file"
    bootstrap_state=$(docker compose --env-file "$supabase_env" --file "$supabase_compose" \
        --file "$SUPABASE_OVERRIDE_FILE" exec -T db \
        psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
        --tuples-only --no-align --command \
        "select (select count(*) from auth.users) || ':' || (select count(*) from public.organizations) || ':' || (select count(*) from public.memberships where user_id=(select auth_user_id from private.mvp_owner_bootstrap where singleton) and status='active' and role='owner') || ':' || (select count(*) from public.devices where id=(select device_id from private.mvp_owner_bootstrap where singleton) and user_id=(select auth_user_id from private.mvp_owner_bootstrap where singleton) and status='active' and key_algorithm='p256' and device_kind='desktop') || ':' || (select count(*) from private.device_sessions where device_id=(select device_id from private.mvp_owner_bootstrap where singleton) and user_id=(select auth_user_id from private.mvp_owner_bootstrap where singleton) and status='active') || ':' || coalesce((select status from private.mvp_owner_bootstrap where singleton),'none');")
    auth_users=${bootstrap_state%%:*}
    bootstrap_tail=${bootstrap_state#*:}
    if [ "$V9_AUTH_HOOK_ENABLED" = false ]; then
        case "$bootstrap_state" in
            0:0:0:0:0:none|0:0:0:0:0:preparing|0:0:0:0:0:failed|1:0:0:0:0:invited) ;;
            *)
                printf '%s\n' "disabled Auth hook is permitted only during the empty-database Owner bootstrap" >&2
                exit 65
                ;;
        esac
        printf '%s\n' "[PREFLIGHT] Owner bootstrap phase is active; public signup remains disabled."
    else
        [ "$auth_users" -ge 1 ] && [ "$auth_users" -le 100 ] && \
            [ "$bootstrap_tail" = "1:1:1:1:finalized" ] || {
            printf '%s\n' "enabled Auth hook requires one finalized Owner, organization, active desktop and session" >&2
            exit 65
        }
    fi
elif [ "${MVP_PREFLIGHT_ALLOW_STOPPED:-false}" = true ]; then
    printf '%s\n' "[PREFLIGHT] Supabase is stopped; live migration/RPC checks are deferred until startup."
else
    printf '%s\n' "Supabase database is not running; live preflight cannot complete" >&2
    exit 70
fi

printf '%s\n' "[PREFLIGHT] Static Compose, host-path and secret-permission checks passed."
printf '%s\n' "[PREFLIGHT] WAF flags and CIDRs are configuration only; this host cannot prove origin isolation."
printf '%s\n' "[PREFLIGHT] Stable release still requires the external v9 deployment evidence origin-isolation gates."
printf '%s\n' "[PREFLIGHT] Runtime TLS, email, Auth hooks, backups and user flows still require live verification."
