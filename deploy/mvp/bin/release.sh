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
backend_manifest=$(python3 "$metadata_tool" --repo "$project_root" --git-sha "$release_sha" \
    --field source_manifest_sha256)
backend_wire=$(python3 "$metadata_tool" --repo "$project_root" --git-sha "$release_sha" \
    --field wire_compatibility)
backend_policy=$(python3 "$metadata_tool" --repo "$project_root" --git-sha "$release_sha" \
    --field migration_policy)

mkdir -p "$state_dir"
chmod 0700 "$state_dir"
exec 9>"$state_dir/.release.lock"
flock -n 9 || { printf '%s\n' "another release or rollback is active" >&2; exit 75; }

current_image=''
current_sha=''
[ ! -f "$state_dir/current.image" ] || current_image=$(tr -d '\r\n' < "$state_dir/current.image")
[ ! -f "$state_dir/current.sha" ] || current_sha=$(tr -d '\r\n' < "$state_dir/current.sha")
if { [ -n "$current_image" ] && [ -z "$current_sha" ]; } || \
   { [ -z "$current_image" ] && [ -n "$current_sha" ]; }; then
    printf '%s\n' "current release state is incomplete" >&2
    exit 65
fi
if [ -n "$current_sha" ]; then
    printf '%s' "$current_sha" | grep -Eq '^[0-9a-f]{40}$' || {
        printf '%s\n' "current release state SHA is invalid" >&2
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
docker compose --env-file "$config_file" --file "$compose_file" config --quiet

if [ -n "$current_image" ]; then
    current_revision=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$current_image")
    [ "$current_revision" = "$current_sha" ] || {
        printf '%s\n' "current Portal image revision differs from retained release state" >&2
        exit 65
    }
    current_manifest=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-source-manifest" }}' "$current_image")
    printf '%s' "$current_manifest" | grep -Eq '^[0-9a-f]{64}$' || {
        printf '%s\n' "current Portal image lacks a valid backend source manifest" >&2
        exit 65
    }
    current_policy=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-migration-policy" }}' "$current_image")
    [ "$current_policy" = expand-contract ] || {
        printf '%s\n' "current Portal image does not declare the required forward migration policy" >&2
        exit 65
    }
    current_wire=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-wire-compatibility" }}' "$current_image")
    [ "$current_wire" = "$backend_wire" ] || {
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
        if [ ! -s "$state_dir/backend.wire" ]; then
            printf '%s\n' "[RELEASE] Active backend wire state is missing; stopping the candidate fail-closed." >&2
            export PORTAL_IMAGE=$candidate_image
            docker compose --env-file "$config_file" --file "$compose_file" stop \
                --timeout 30 portal edge >/dev/null 2>&1 || true
            return 1
        fi
        active_backend_wire=$(tr -d '\r\n' < "$state_dir/backend.wire")
        if [ "$current_wire" != "$active_backend_wire" ]; then
            printf '%s\n' "[RELEASE] Refusing incompatible Portal restore; stopping the candidate fail-closed." >&2
            export PORTAL_IMAGE=$candidate_image
            docker compose --env-file "$config_file" --file "$compose_file" stop \
                --timeout 30 portal edge >/dev/null 2>&1 || true
            return 1
        fi
        printf '%s\n' "[RELEASE] Candidate failed; restoring the wire-compatible retained Portal image."
        export PORTAL_IMAGE=$current_image
        docker compose --env-file "$config_file" --file "$compose_file" up \
            --detach --wait --wait-timeout 180 portal edge >/dev/null 2>&1 || true
    else
        export PORTAL_IMAGE=$candidate_image
        docker compose --env-file "$config_file" --file "$compose_file" stop \
            --timeout 30 portal edge >/dev/null 2>&1 || true
    fi
}

export PORTAL_IMAGE=$candidate_image
if ! docker compose --env-file "$config_file" --file "$compose_file" up \
    --detach --wait --wait-timeout 180 portal edge; then
    restore_current
    exit 70
fi

if ! python3 "$script_dir/probe-public.py" "$config_file"; then
    restore_current
    exit 70
fi

if [ -n "$current_image" ] && [ "$current_image" != "$candidate_image" ]; then
    printf '%s\n' "$current_image" > "$state_dir/.previous.image.tmp"
    printf '%s\n' "$current_sha" > "$state_dir/.previous.sha.tmp"
    printf '%s\n' "$current_wire" > "$state_dir/.previous.wire.tmp"
    printf '%s\n' "$current_manifest" > "$state_dir/.previous.manifest.tmp"
    mv -f "$state_dir/.previous.image.tmp" "$state_dir/previous.image"
    mv -f "$state_dir/.previous.sha.tmp" "$state_dir/previous.sha"
    mv -f "$state_dir/.previous.wire.tmp" "$state_dir/previous.wire"
    mv -f "$state_dir/.previous.manifest.tmp" "$state_dir/previous.manifest"
fi
printf '%s\n' "$candidate_image" > "$state_dir/.current.image.tmp"
printf '%s\n' "$release_sha" > "$state_dir/.current.sha.tmp"
printf '%s\n' "$candidate_wire" > "$state_dir/.current.wire.tmp"
printf '%s\n' "$candidate_manifest" > "$state_dir/.current.manifest.tmp"
mv -f "$state_dir/.current.image.tmp" "$state_dir/current.image"
mv -f "$state_dir/.current.sha.tmp" "$state_dir/current.sha"
mv -f "$state_dir/.current.wire.tmp" "$state_dir/current.wire"
mv -f "$state_dir/.current.manifest.tmp" "$state_dir/current.manifest"
chmod 0600 "$state_dir"/*.image "$state_dir"/*.sha "$state_dir"/*.wire "$state_dir"/*.manifest

printf '%s\n' "[RELEASE] Portal/Supabase public probe and exact backend release verification passed."
printf '%s\n' "[RELEASE] Current Git SHA: $release_sha"
printf '%s\n' "[RELEASE] The previous image digest remains retained for compatible Portal rollback; backend state was not rolled back."
