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
exec 9>"$state_dir/.release.lock"
flock -n 9 || { printf '%s\n' "another release or rollback is active" >&2; exit 75; }

for state_file in \
    current.image current.sha current.wire current.manifest \
    previous.image previous.sha previous.wire previous.manifest \
    backend.sha backend.manifest backend.wire backend.policy \
    backend.functions backend.upstream; do
    [ -s "$state_dir/$state_file" ] || {
        printf '%s\n' "rollback state is incomplete: $state_file" >&2
        exit 66
    }
done

current_image=$(tr -d '\r\n' < "$state_dir/current.image")
current_sha=$(tr -d '\r\n' < "$state_dir/current.sha")
current_wire=$(tr -d '\r\n' < "$state_dir/current.wire")
current_manifest=$(tr -d '\r\n' < "$state_dir/current.manifest")
previous_image=$(tr -d '\r\n' < "$state_dir/previous.image")
previous_sha=$(tr -d '\r\n' < "$state_dir/previous.sha")
previous_wire=$(tr -d '\r\n' < "$state_dir/previous.wire")
previous_manifest=$(tr -d '\r\n' < "$state_dir/previous.manifest")
backend_sha=$(tr -d '\r\n' < "$state_dir/backend.sha")
backend_wire=$(tr -d '\r\n' < "$state_dir/backend.wire")

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

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compose_file="$script_dir/../docker-compose.production.yml"

# This validates the database active row, migration ledger, function digest,
# official upstream SHA and every backend.* host-state file before a Portal
# rollback is considered.
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
docker compose --env-file "$config_file" --file "$compose_file" config --quiet
restore_displaced() {
    export PORTAL_IMAGE=$current_image
    docker compose --env-file "$config_file" --file "$compose_file" up \
        --detach --wait --wait-timeout 180 portal edge >/dev/null 2>&1 || true
}
if ! docker compose --env-file "$config_file" --file "$compose_file" up \
    --detach --wait --wait-timeout 180 portal edge; then
    restore_displaced
    exit 70
fi
if ! python3 "$script_dir/probe-public.py" "$config_file"; then
    restore_displaced
    exit 70
fi

printf '%s\n' "$previous_image" > "$state_dir/.current.image.tmp"
printf '%s\n' "$previous_sha" > "$state_dir/.current.sha.tmp"
printf '%s\n' "$previous_wire" > "$state_dir/.current.wire.tmp"
printf '%s\n' "$previous_manifest" > "$state_dir/.current.manifest.tmp"
printf '%s\n' "$current_image" > "$state_dir/.previous.image.tmp"
printf '%s\n' "$current_sha" > "$state_dir/.previous.sha.tmp"
printf '%s\n' "$current_wire" > "$state_dir/.previous.wire.tmp"
printf '%s\n' "$current_manifest" > "$state_dir/.previous.manifest.tmp"
for state_name in image sha wire manifest; do
    mv -f "$state_dir/.current.$state_name.tmp" "$state_dir/current.$state_name"
    mv -f "$state_dir/.previous.$state_name.tmp" "$state_dir/previous.$state_name"
done
chmod 0600 "$state_dir"/*.image "$state_dir"/*.sha "$state_dir"/*.wire "$state_dir"/*.manifest

printf '%s\n' "[ROLLBACK] Restored retained wire-compatible Portal Git SHA: $previous_sha"
printf '%s\n' "[ROLLBACK] Active backend remained at Git SHA: $backend_sha"
printf '%s\n' "[ROLLBACK] Displaced Portal image retained as the next roll-forward candidate."
