#!/bin/sh
set -eu
umask 077

usage() {
    printf '%s\n' "usage: $0 IMAGE_REPOSITORY FULL_GIT_SHA REPOSITORY_AT_SHA256 [PRODUCTION_ENV]" >&2
    exit 64
}
[ "$#" -ge 3 ] && [ "$#" -le 4 ] || usage
image_repository=$1
release_sha=$2
candidate_image=$3
config_file=${4:-/etc/defense-tracker/production.env}

printf '%s' "$release_sha" | grep -Eq '^[0-9a-f]{40}$' || {
    printf '%s\n' "release SHA must be 40 lowercase hexadecimal characters" >&2
    exit 64
}
printf '%s' "$image_repository" | grep -Eq '^[A-Za-z0-9._/-]+$' || {
    printf '%s\n' "image repository must not contain a tag or unsafe characters" >&2
    exit 64
}
case "$candidate_image" in
    "$image_repository"@sha256:*) ;;
    *) printf '%s\n' "candidate image must be the requested repository pinned by digest" >&2; exit 64 ;;
esac
candidate_digest=${candidate_image#"$image_repository"@}
printf '%s' "$candidate_digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
    printf '%s\n' "candidate image digest must be a full lowercase sha256" >&2
    exit 64
}
[ -f "$config_file" ] || { printf '%s\n' "production env file is missing" >&2; exit 66; }
set -a
# shellcheck disable=SC1090
. "$config_file"
set +a

: "${PORTAL_DOMAIN:?PORTAL_DOMAIN is required}"
: "${API_DOMAIN:?API_DOMAIN is required}"
: "${MVP_RELEASE_STATE_DIR:?MVP_RELEASE_STATE_DIR is required}"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
compose_file="$script_dir/../docker-compose.production.yml"
state_dir=$MVP_RELEASE_STATE_DIR
case "$state_dir" in /*) ;; *) printf '%s\n' "release state path must be absolute" >&2; exit 64 ;; esac

actual_release_sha=$(git -C "$project_root" rev-parse HEAD 2>/dev/null || true)
[ "$actual_release_sha" = "$release_sha" ] || {
    printf '%s\n' "project checkout HEAD does not match requested release SHA" >&2
    exit 65
}
[ -z "$(git -C "$project_root" status --porcelain --untracked-files=all)" ] || {
    printf '%s\n' "project checkout must be clean before release" >&2
    exit 65
}
metadata_tool="$script_dir/backend-release-metadata.py"
state_tool="$script_dir/release-state.py"
lock_tool="$script_dir/deployment-lock.sh"
backend_manifest=$(python3 "$metadata_tool" --repo "$project_root" --git-sha "$release_sha" \
    --field source_manifest_sha256)
backend_wire=$(python3 "$metadata_tool" --repo "$project_root" --git-sha "$release_sha" \
    --field wire_compatibility)
backend_policy=$(python3 "$metadata_tool" --repo "$project_root" --git-sha "$release_sha" \
    --field migration_policy)

python3 "$state_tool" prepare "$state_dir"
# shellcheck disable=SC1090
. "$lock_tool"
acquire_mvp_deployment_lock "$state_dir"
python3 "$state_tool" migrate portal "$state_dir" >/dev/null
python3 "$state_tool" portal-intent-check "$state_dir"

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

current_image=''
current_sha=''
current_wire=''
current_manifest=''
# portal-state.json is the only authoritative current/previous generation.
if python3 "$state_tool" exists portal "$state_dir"; then
    current_image=$(python3 "$state_tool" get portal "$state_dir" current.image)
    current_sha=$(python3 "$state_tool" get portal "$state_dir" current.release_sha)
    current_wire=$(python3 "$state_tool" get portal "$state_dir" current.wire_compatibility)
    current_manifest=$(python3 "$state_tool" get portal "$state_dir" current.source_manifest_sha256)
fi

observed_image=$(running_portal_image "${current_image:-$candidate_image}")
if [ -n "$current_image" ]; then
    [ "$observed_image" = "$current_image" ] || {
        printf '%s\n' "running Portal image differs from authoritative release state" >&2
        exit 65
    }
    observed_commit=$(running_portal_commit "$current_image" "$current_sha")
    [ "$observed_commit" = "$current_sha" ] || {
        printf '%s\n' "running Portal commit differs from authoritative release state" >&2
        exit 65
    }
else
    [ "$observed_image" = none ] || {
        printf '%s\n' "a running Portal exists without authoritative release state" >&2
        exit 65
    }
fi

# Candidate acquisition, immutable-label checks and Compose rendering all
# happen before install-supabase-app can write a function tree or database.
printf '%s\n' "[RELEASE] Pulling approved immutable candidate image digest."
docker pull "$candidate_image"
revision=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$candidate_image")
[ "$revision" = "$release_sha" ] || {
    printf '%s\n' "candidate image revision label does not match requested Git SHA" >&2
    exit 65
}
candidate_manifest=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-source-manifest" }}' "$candidate_image")
[ "$candidate_manifest" = "$backend_manifest" ] || {
    printf '%s\n' "candidate image backend source manifest does not match the exact release" >&2
    exit 65
}
candidate_wire=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-wire-compatibility" }}' "$candidate_image")
[ "$candidate_wire" = "$backend_wire" ] || {
    printf '%s\n' "candidate image backend wire compatibility does not match the exact release" >&2
    exit 65
}
candidate_policy=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-migration-policy" }}' "$candidate_image")
[ "$candidate_policy" = "$backend_policy" ] || {
    printf '%s\n' "candidate image backend migration policy does not match the exact release" >&2
    exit 65
}

export PORTAL_IMAGE=$candidate_image
export MVP_EXPECTED_RELEASE_SHA=$release_sha
docker compose --env-file "$config_file" --file "$compose_file" config --quiet

if [ -n "$current_image" ]; then
    current_revision=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$current_image")
    [ "$current_revision" = "$current_sha" ] || {
        printf '%s\n' "current Portal image revision differs from retained release state" >&2
        exit 65
    }
    current_label_manifest=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-source-manifest" }}' "$current_image")
    [ "$current_label_manifest" = "$current_manifest" ] || {
        printf '%s\n' "current Portal image lacks a valid backend source manifest" >&2
        exit 65
    }
    current_policy=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-migration-policy" }}' "$current_image")
    [ "$current_policy" = expand-contract ] || {
        printf '%s\n' "current Portal image does not declare the required forward migration policy" >&2
        exit 65
    }
    current_label_wire=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-wire-compatibility" }}' "$current_image")
    [ "$current_label_wire" = "$current_wire" ] && [ "$current_wire" = "$backend_wire" ] || {
        printf '%s\n' "current Portal is not compatible with the candidate backend wire contract" >&2
        exit 65
    }
fi

printf '%s\n' "[RELEASE] Compatibility gate passed; backend migrations are forward-only."
"$script_dir/install-supabase-app.sh" "$release_sha" "$config_file"
"$script_dir/verify-supabase-app.sh" "$release_sha" "$config_file"
MVP_EXPECTED_RELEASE_SHA=$release_sha "$script_dir/preflight.sh" "$config_file"

restore_current() {
    if [ -n "$current_image" ]; then
        if ! python3 "$state_tool" exists backend "$state_dir"; then
            printf '%s\n' "[RELEASE] Active backend wire state is missing; stopping the candidate fail-closed." >&2
            export PORTAL_IMAGE=$candidate_image
            docker compose --env-file "$config_file" --file "$compose_file" stop \
                --timeout 30 portal edge >/dev/null 2>&1 || true
            return 1
        fi
        active_backend_wire=$(python3 "$state_tool" get backend "$state_dir" active.wire_compatibility)
        if [ "$current_wire" != "$active_backend_wire" ]; then
            printf '%s\n' "[RELEASE] Refusing incompatible Portal restore; stopping the candidate fail-closed." >&2
            export PORTAL_IMAGE=$candidate_image
            docker compose --env-file "$config_file" --file "$compose_file" stop \
                --timeout 30 portal edge >/dev/null 2>&1 || true
            return 1
        fi
        printf '%s\n' "[RELEASE] Candidate failed; restoring the wire-compatible retained Portal image."
        export PORTAL_IMAGE=$current_image
        export MVP_EXPECTED_RELEASE_SHA=$current_sha
        docker compose --env-file "$config_file" --file "$compose_file" up \
            --detach --wait --wait-timeout 180 portal edge >/dev/null 2>&1 || true
    else
        export PORTAL_IMAGE=$candidate_image
        docker compose --env-file "$config_file" --file "$compose_file" stop \
            --timeout 30 portal edge >/dev/null 2>&1 || true
        for service in portal edge; do
            running_id=$(PORTAL_IMAGE="$candidate_image" \
                MVP_EXPECTED_RELEASE_SHA="$release_sha" docker compose \
                --env-file "$config_file" --file "$compose_file" \
                ps --status running --quiet "$service")
            [ -z "$running_id" ] || {
                printf '%s\n' "initial Portal rollback left a public service running" >&2
                return 1
            }
        done
    fi
    restored_image=$(running_portal_image "${current_image:-$candidate_image}")
    if [ -n "$current_image" ]; then
        python3 "$script_dir/probe-public.py" "$config_file" "$current_sha"
    fi
    python3 "$state_tool" portal-intent-abort "$state_dir" "$restored_image"
}

python3 "$state_tool" portal-intent-begin "$state_dir" promote \
    "$candidate_image" "$release_sha" "$candidate_wire" "$candidate_manifest"
export PORTAL_IMAGE=$candidate_image
export MVP_EXPECTED_RELEASE_SHA=$release_sha
if ! docker compose --env-file "$config_file" --file "$compose_file" up \
    --detach --wait --wait-timeout 180 portal edge; then
    restore_current
    exit 70
fi

if ! python3 "$script_dir/probe-public.py" "$config_file" "$release_sha"; then
    restore_current
    exit 70
fi

observed_image=$(running_portal_image "$candidate_image")
python3 "$state_tool" portal-intent-complete "$state_dir" "$observed_image"

printf '%s\n' "[RELEASE] Portal/Supabase public probe and exact backend release verification passed."
printf '%s\n' "[RELEASE] Current Git SHA: $release_sha"
printf '%s\n' "[RELEASE] The previous image digest remains retained for compatible Portal rollback; backend state was not rolled back."
