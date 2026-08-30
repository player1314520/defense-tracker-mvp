#!/bin/sh
set -eu
umask 077

config_file=${1:-/etc/defense-tracker/production.env}
[ -f "$config_file" ] || {
    printf '%s\n' "production env file is missing" >&2
    exit 66
}
set -a
# shellcheck disable=SC1090
. "$config_file"
set +a
: "${PORTAL_DOMAIN:?PORTAL_DOMAIN is required}"
: "${API_DOMAIN:?API_DOMAIN is required}"
: "${MVP_RELEASE_STATE_DIR:?MVP_RELEASE_STATE_DIR is required}"

state_dir=$MVP_RELEASE_STATE_DIR
case "$state_dir" in /*) ;; *) printf '%s\n' "release state path must be absolute" >&2; exit 64 ;; esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
state_tool="$script_dir/release-state.py"
compose_file="$script_dir/../docker-compose.production.yml"

python3 "$state_tool" check-dir "$state_dir"
# shellcheck disable=SC1090
. "$script_dir/deployment-lock.sh"
acquire_mvp_deployment_lock "$state_dir"

target_image=$(python3 "$state_tool" portal-intent-get "$state_dir" to_release.image)
target_sha=$(python3 "$state_tool" portal-intent-get "$state_dir" to_release.release_sha)
base_generation=$(python3 "$state_tool" portal-intent-get "$state_dir" base_generation)
if [ "$base_generation" = 0 ]; then
    source_image=none
    source_sha=none
else
    source_image=$(python3 "$state_tool" portal-intent-get "$state_dir" from_release.image)
    source_sha=$(python3 "$state_tool" portal-intent-get "$state_dir" from_release.release_sha)
fi

container_id=$(PORTAL_IMAGE="$target_image" docker compose \
    --env-file "$config_file" --file "$compose_file" ps --all --quiet portal)
if [ -z "$container_id" ]; then
    observed_image=none
else
    printf '%s' "$container_id" | grep -Eq '^[0-9a-f]{12,64}$' || {
        printf '%s\n' "Portal container identity is invalid or ambiguous" >&2
        exit 65
    }
    running=$(docker inspect --format '{{.State.Running}}' "$container_id")
    if [ "$running" = true ]; then
        observed_image=$(docker inspect --format '{{.Config.Image}}' "$container_id")
        observed_commit=$(docker inspect \
            --format '{{range .Config.Env}}{{println .}}{{end}}' "$container_id" | \
            awk -F= '$1 == "DEFENSE_TRACKER_BUILD_COMMIT" { sub(/^[^=]*=/, ""); print }')
    else
        observed_image=none
        observed_commit=none
    fi
fi
if [ -z "${observed_commit:-}" ]; then
    observed_commit=none
fi

verify_live_portal() {
    expected_sha=$1
    python3 "$state_tool" migrate backend "$state_dir" >/dev/null
    backend_sha=$(python3 "$state_tool" get backend "$state_dir" active.release_sha)
    "$script_dir/verify-supabase-app.sh" "$backend_sha" "$config_file"
    python3 "$script_dir/probe-public.py" "$config_file" "$expected_sha"
}

if [ "$observed_image" = "$target_image" ]; then
    [ "$observed_commit" = "$target_sha" ] || {
        printf '%s\n' "running Portal commit differs from the switch intent target" >&2
        exit 65
    }
    verify_live_portal "$target_sha"
    python3 "$state_tool" portal-intent-complete "$state_dir" "$observed_image"
    printf '%s\n' "[RECOVERY] Verified and committed interrupted Portal target: $target_sha"
elif [ "$observed_image" = "$source_image" ]; then
    if [ "$source_image" != none ]; then
        [ "$observed_commit" = "$source_sha" ] || {
            printf '%s\n' "running Portal commit differs from the switch intent source" >&2
            exit 65
        }
        verify_live_portal "$source_sha"
    else
        PORTAL_IMAGE="$target_image" MVP_EXPECTED_RELEASE_SHA="$target_sha" \
            docker compose --env-file "$config_file" --file "$compose_file" stop \
            --timeout 30 portal edge
        for service in portal edge; do
            running_id=$(PORTAL_IMAGE="$target_image" \
                MVP_EXPECTED_RELEASE_SHA="$target_sha" docker compose \
                --env-file "$config_file" --file "$compose_file" \
                ps --status running --quiet "$service")
            [ -z "$running_id" ] || {
                printf '%s\n' "initial Portal recovery left a public service running" >&2
                exit 70
            }
        done
    fi
    python3 "$state_tool" portal-intent-abort "$state_dir" "$observed_image"
    printf '%s\n' "[RECOVERY] Verified the pre-switch runtime and aborted the interrupted switch."
else
    printf '%s\n' "running Portal image matches neither side of the durable switch intent" >&2
    exit 65
fi
