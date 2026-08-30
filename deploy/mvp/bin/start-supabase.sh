#!/bin/sh
set -eu

config_file=${1:-/etc/defense-tracker/production.env}
[ -f "$config_file" ] || { printf '%s\n' "production env file is missing" >&2; exit 66; }
set -a
# shellcheck disable=SC1090
. "$config_file"
set +a
: "${SUPABASE_STACK_DIR:?SUPABASE_STACK_DIR is required}"
: "${SUPABASE_OVERRIDE_FILE:?SUPABASE_OVERRIDE_FILE is required}"
: "${MVP_RELEASE_STATE_DIR:?MVP_RELEASE_STATE_DIR is required}"

base="$SUPABASE_STACK_DIR/docker-compose.yml"
upstream_env="$SUPABASE_STACK_DIR/.env"
[ -f "$base" ] && [ -f "$upstream_env" ] && [ -f "$SUPABASE_OVERRIDE_FILE" ] || {
    printf '%s\n' "pinned official Supabase stack or production override is missing" >&2
    exit 66
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
state_tool="$script_dir/release-state.py"
python3 "$state_tool" prepare "$MVP_RELEASE_STATE_DIR"
# shellcheck disable=SC1090
. "$script_dir/deployment-lock.sh"
acquire_mvp_deployment_lock "$MVP_RELEASE_STATE_DIR"
release_sha=$(git -C "$project_root" rev-parse HEAD 2>/dev/null || true)
printf '%s' "$release_sha" | grep -Eq '^[0-9a-f]{40}$' || {
    printf '%s\n' "unable to resolve the project release SHA" >&2
    exit 65
}
"$script_dir/install-supabase-app.sh" --prepare-functions "$release_sha" "$config_file"
MVP_PREFLIGHT_ALLOW_STOPPED=true MVP_EXPECTED_RELEASE_SHA=$release_sha \
    "$script_dir/preflight.sh" "$config_file"

docker compose --env-file "$upstream_env" --file "$base" \
    --file "$SUPABASE_OVERRIDE_FILE" config --quiet
docker compose --env-file "$upstream_env" --file "$base" \
    --file "$SUPABASE_OVERRIDE_FILE" pull
docker compose --env-file "$upstream_env" --file "$base" \
    --file "$SUPABASE_OVERRIDE_FILE" up --detach --wait --wait-timeout 300

"$script_dir/install-supabase-app.sh" "$release_sha" "$config_file"
MVP_EXPECTED_RELEASE_SHA=$release_sha "$script_dir/preflight.sh" "$config_file"

printf '%s\n' "[SUPABASE] Pinned official stack, migrations and Edge Functions are healthy."
printf '%s\n' "[SUPABASE] No reset, data deletion or public Studio exposure was performed."
