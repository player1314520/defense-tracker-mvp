#!/bin/sh
set -eu
umask 077

config_file=${1:-/etc/defense-tracker/production.env}
[ -f "$config_file" ] || { printf '%s\n' "production env file is missing" >&2; exit 66; }
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
python3 "$state_tool" check-dir "$state_dir"
# shellcheck disable=SC1090
. "$script_dir/deployment-lock.sh"
acquire_mvp_deployment_lock "$state_dir"
python3 "$state_tool" migrate portal "$state_dir" >/dev/null
python3 "$state_tool" migrate backend "$state_dir" >/dev/null
python3 "$state_tool" portal-intent-check "$state_dir"

# portal-state.json and backend-state.json each expose one complete generation.
current_image=$(python3 "$state_tool" get portal "$state_dir" current.image)
current_sha=$(python3 "$state_tool" get portal "$state_dir" current.release_sha)
current_wire=$(python3 "$state_tool" get portal "$state_dir" current.wire_compatibility)
current_manifest=$(python3 "$state_tool" get portal "$state_dir" current.source_manifest_sha256)
previous_image=$(python3 "$state_tool" get portal "$state_dir" previous.image)
previous_sha=$(python3 "$state_tool" get portal "$state_dir" previous.release_sha)
previous_wire=$(python3 "$state_tool" get portal "$state_dir" previous.wire_compatibility)
previous_manifest=$(python3 "$state_tool" get portal "$state_dir" previous.source_manifest_sha256)
backend_sha=$(python3 "$state_tool" get backend "$state_dir" active.release_sha)
backend_wire=$(python3 "$state_tool" get backend "$state_dir" active.wire_compatibility)

for retained_image in "$current_image" "$previous_image"; do
    printf '%s' "$retained_image" | grep -Eq '^[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$' || {
        printf '%s\n' "retained Portal image must be pinned by repository digest" >&2
        exit 65
    }
done

for retained_sha in "$current_sha" "$previous_sha" "$backend_sha"; do
    printf '%s' "$retained_sha" | grep -Eq '^[0-9a-f]{40}$' || {
        printf '%s\n' "retained release SHA is invalid" >&2
        exit 65
    }
done
for retained_manifest in "$current_manifest" "$previous_manifest"; do
    printf '%s' "$retained_manifest" | grep -Eq '^[0-9a-f]{64}$' || {
        printf '%s\n' "retained Portal backend manifest is invalid" >&2
        exit 65
    }
done

compose_file="$script_dir/../docker-compose.production.yml"

running_portal_image() {
    lookup_image=$1
    container_id=$(PORTAL_IMAGE="$lookup_image" docker compose \
        --env-file "$config_file" --file "$compose_file" ps --all --quiet portal)
    if [ -z "$container_id" ]; then
        printf '%s\n' none
        return 0
    fi
    printf '%s' "$container_id" | grep -Eq '^[0-9a-f]{12,64}$' || {
        printf '%s\n' "Portal container identity is invalid or ambiguous" >&2
        return 65
    }
    running=$(docker inspect --format '{{.State.Running}}' "$container_id")
    if [ "$running" != true ]; then
        printf '%s\n' none
        return 0
    fi
    docker inspect --format '{{.Config.Image}}' "$container_id"
}

running_portal_commit() {
    lookup_image=$1
    lookup_sha=$2
    container_id=$(PORTAL_IMAGE="$lookup_image" MVP_EXPECTED_RELEASE_SHA="$lookup_sha" \
        docker compose --env-file "$config_file" --file "$compose_file" \
        ps --all --quiet portal)
    if [ -z "$container_id" ]; then
        printf '%s\n' none
        return 0
    fi
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container_id" | \
        awk -F= '$1 == "DEFENSE_TRACKER_BUILD_COMMIT" { sub(/^[^=]*=/, ""); print }'
}

observed_image=$(running_portal_image "$current_image")
[ "$observed_image" = "$current_image" ] || {
    printf '%s\n' "running Portal image differs from authoritative release state" >&2
    exit 65
}
observed_commit=$(running_portal_commit "$current_image" "$current_sha")
[ "$observed_commit" = "$current_sha" ] || {
    printf '%s\n' "running Portal commit differs from authoritative release state" >&2
    exit 65
}

# This validates the database active row, migration ledger, function digest,
# official upstream SHA and the complete backend-state.json generation before
# a Portal rollback is considered.
"$script_dir/verify-supabase-app.sh" "$backend_sha" "$config_file"

current_revision=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$current_image")
current_label_wire=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-wire-compatibility" }}' "$current_image")
current_label_manifest=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-source-manifest" }}' "$current_image")
[ "$current_revision" = "$current_sha" ] && \
    [ "$current_label_wire" = "$current_wire" ] && \
    [ "$current_label_manifest" = "$current_manifest" ] && \
    [ "$current_wire" = "$backend_wire" ] || {
    printf '%s\n' "current Portal image labels differ from retained release state" >&2
    exit 65
}

revision=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$previous_image")
[ "$revision" = "$previous_sha" ] || {
    printf '%s\n' "retained rollback image revision label is invalid" >&2
    exit 65
}
rollback_manifest=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-source-manifest" }}' "$previous_image")
[ "$rollback_manifest" = "$previous_manifest" ] || {
    printf '%s\n' "retained rollback image backend source manifest is invalid" >&2
    exit 65
}
rollback_policy=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-migration-policy" }}' "$previous_image")
[ "$rollback_policy" = expand-contract ] || {
    printf '%s\n' "retained rollback image lacks the required forward migration policy" >&2
    exit 65
}
rollback_wire=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-wire-compatibility" }}' "$previous_image")
[ "$rollback_wire" = "$previous_wire" ] || {
    printf '%s\n' "retained rollback image wire label differs from release state" >&2
    exit 65
}
[ "$rollback_wire" = "$backend_wire" ] || {
    printf '%s\n' "rollback Portal is incompatible with the active backend wire contract" >&2
    exit 65
}

export PORTAL_IMAGE=$previous_image
export MVP_EXPECTED_RELEASE_SHA=$previous_sha
docker compose --env-file "$config_file" --file "$compose_file" config --quiet
restore_displaced() {
    export PORTAL_IMAGE=$current_image
    export MVP_EXPECTED_RELEASE_SHA=$current_sha
    docker compose --env-file "$config_file" --file "$compose_file" up \
        --detach --wait --wait-timeout 180 portal edge >/dev/null 2>&1 || true
    restored_image=$(running_portal_image "$current_image")
    python3 "$script_dir/probe-public.py" "$config_file" "$current_sha"
    python3 "$state_tool" portal-intent-abort "$state_dir" "$restored_image"
}
python3 "$state_tool" portal-intent-begin "$state_dir" rollback \
    "$previous_image" "$previous_sha" "$previous_wire" "$previous_manifest"
if ! docker compose --env-file "$config_file" --file "$compose_file" up \
    --detach --wait --wait-timeout 180 portal edge; then
    restore_displaced
    exit 70
fi
if ! python3 "$script_dir/probe-public.py" "$config_file" "$previous_sha"; then
    restore_displaced
    exit 70
fi

observed_image=$(running_portal_image "$previous_image")
python3 "$state_tool" portal-intent-complete "$state_dir" "$observed_image"

printf '%s\n' "[ROLLBACK] Restored retained wire-compatible Portal Git SHA: $previous_sha"
printf '%s\n' "[ROLLBACK] Active backend remained at Git SHA: $backend_sha"
printf '%s\n' "[ROLLBACK] Displaced Portal image retained as the next roll-forward candidate."
