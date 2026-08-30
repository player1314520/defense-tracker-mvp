#!/bin/sh
set -eu
umask 077

config_file=${MVP_PRODUCTION_ENV:-/etc/defense-tracker/production.env}
[ -f "$config_file" ] || { printf '%s\n' "backup configuration is missing" >&2; exit 64; }
set -a
# shellcheck disable=SC1090
. "$config_file"
set +a

require_value() {
    eval "candidate=\${$1:-}"
    [ -n "$candidate" ] || { printf '%s\n' "required backup setting is empty: $1" >&2; exit 64; }
}
for name in MVP_RELEASE_STATE_DIR SUPABASE_STACK_DIR SUPABASE_UPSTREAM_SHA SUPABASE_OVERRIDE_FILE SUPABASE_STORAGE_DATA_DIR SUPABASE_CONFIG_DIR MVP_CONFIG_DIR BACKUP_STAGING_DIR BACKUP_REMOTE AGE_RECIPIENT_FILE RCLONE_CONFIG; do
    require_value "$name"
done

for command_name in docker age rclone flock tar sha256sum git python3; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf '%s\n' "required preinstalled backup command is missing: $command_name" >&2
        exit 69
    }
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
state_tool="$script_dir/release-state.py"

stack_compose="$SUPABASE_STACK_DIR/docker-compose.yml"
stack_env="$SUPABASE_STACK_DIR/.env"
[ -f "$stack_compose" ] && [ -f "$stack_env" ] && [ -f "$SUPABASE_OVERRIDE_FILE" ] || {
    printf '%s\n' "official Supabase Compose checkout is incomplete" >&2
    exit 66
}
actual_supabase_sha=$(git -C "$SUPABASE_STACK_DIR" rev-parse HEAD 2>/dev/null || true)
[ "$actual_supabase_sha" = "$SUPABASE_UPSTREAM_SHA" ] || {
    printf '%s\n' "backup stack differs from the approved Supabase commit" >&2
    exit 65
}
[ -d "$SUPABASE_STORAGE_DATA_DIR" ] && [ -d "$SUPABASE_CONFIG_DIR" ] && [ -d "$MVP_CONFIG_DIR" ] || {
    printf '%s\n' "Storage or configuration backup source is missing" >&2
    exit 66
}
[ -r "$AGE_RECIPIENT_FILE" ] && [ -r "$RCLONE_CONFIG" ] || {
    printf '%s\n' "backup encryption or offsite transport configuration is unreadable" >&2
    exit 77
}

python3 "$state_tool" prepare "$BACKUP_STAGING_DIR"

exec 6>"$BACKUP_STAGING_DIR/.backup.lock"
flock -n 6 || { printf '%s\n' "another backup is already running" >&2; exit 75; }
python3 "$state_tool" prepare "$MVP_RELEASE_STATE_DIR"
# shellcheck disable=SC1090
. "$script_dir/deployment-lock.sh"
acquire_mvp_deployment_lock "$MVP_RELEASE_STATE_DIR"
exec 8>"$MVP_RELEASE_STATE_DIR/.supabase-app.lock"
flock -n 8 || { printf '%s\n' "a Supabase application install is active" >&2; exit 75; }

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir=$(mktemp -d "$BACKUP_STAGING_DIR/plain-$timestamp-XXXXXX")
bundle="$BACKUP_STAGING_DIR/defense-tracker-$timestamp.tar"
encrypted="$bundle.age"
encrypted_checksum="$encrypted.sha256"
write_services_stopped=false

compose() {
    docker compose --env-file "$stack_env" --file "$stack_compose" \
        --file "$SUPABASE_OVERRIDE_FILE" "$@"
}

resume_write_services() {
    [ "$write_services_stopped" = true ] || return 0
    compose up --detach --wait --wait-timeout 300 \
        kong auth rest realtime storage imgproxy functions meta studio supavisor
    write_services_stopped=false
    printf '%s\n' "[BACKUP] Write services resumed after the maintenance snapshot."
}

safe_cleanup() {
    if [ "$write_services_stopped" = true ]; then
        compose up --detach \
            kong auth rest realtime storage imgproxy functions meta studio supavisor \
            >/dev/null 2>&1 || true
        write_services_stopped=false
    fi
    if [ -n "${run_dir:-}" ] && [ -d "$run_dir" ]; then
        case "$run_dir" in "$BACKUP_STAGING_DIR"/plain-*) find "$run_dir" -depth -delete ;; esac
    fi
    for temporary_file in "${bundle:-}" "${encrypted:-}" "${encrypted_checksum:-}"; do
        if [ -n "$temporary_file" ] && [ -f "$temporary_file" ]; then
            case "$temporary_file" in "$BACKUP_STAGING_DIR"/*) rm -f -- "$temporary_file" ;; esac
        fi
    done
}
trap safe_cleanup EXIT HUP INT TERM

printf '%s\n' "[BACKUP] Creating encrypted backup candidate."
compose stop --timeout 60 kong auth rest realtime storage imgproxy functions meta studio supavisor
write_services_stopped=true
printf '%s\n' "[BACKUP] Write services stopped for the maintenance snapshot."
(
    cd "$SUPABASE_STACK_DIR"
    compose exec -T db \
        pg_dumpall --globals-only --no-role-passwords --username postgres \
        > "$run_dir/postgres-globals.sql"
    compose exec -T db psql --username postgres --dbname postgres \
        --tuples-only --no-align --command \
        "select rolname from pg_roles order by rolname;" \
        > "$run_dir/postgres-roles.txt"
    database_names=$(compose exec -T db psql --username postgres --dbname postgres \
        --tuples-only --no-align --command \
        "select datname from pg_database where datistemplate=false order by datname;")
    [ "$database_names" = "_supabase
postgres" ] || {
        printf '%s\n' "unexpected database set; backup allowlist requires review" >&2
        exit 65
    }
    compose exec -T db pg_dump --format=custom --serializable-deferrable \
        --username postgres --dbname postgres > "$run_dir/postgres.dump"
    compose exec -T db pg_dump --format=custom --serializable-deferrable \
        --username postgres --dbname _supabase > "$run_dir/_supabase.dump"
    compose exec -T db \
        tar --create --file - --directory /etc/postgresql-custom . \
        > "$run_dir/db-config.tar"
)
[ -s "$run_dir/postgres-globals.sql" ] && [ -s "$run_dir/postgres-roles.txt" ] && \
    [ -s "$run_dir/postgres.dump" ] && [ -s "$run_dir/_supabase.dump" ] || {
        printf '%s\n' "Postgres backup payload is incomplete" >&2
        exit 65
    }
compose exec -T db pg_restore --list < "$run_dir/postgres.dump" >/dev/null
compose exec -T db pg_restore --list < "$run_dir/_supabase.dump" >/dev/null
tar --file "$run_dir/db-config.tar" --list >/dev/null

storage_parent=$(dirname -- "$SUPABASE_STORAGE_DATA_DIR")
storage_name=$(basename -- "$SUPABASE_STORAGE_DATA_DIR")
tar --acls --xattrs --numeric-owner --file "$run_dir/storage.tar" \
    --create --directory "$storage_parent" "$storage_name"
tar --file "$run_dir/storage.tar" --list >/dev/null

# DB metadata and file bytes now represent the same quiesced interval.  Resume
# traffic before CPU/network-heavy encryption and offsite transfer.
resume_write_services

tar --acls --xattrs --numeric-owner --file "$run_dir/supabase-config.tar" --create \
    --directory "$SUPABASE_CONFIG_DIR" \
    --exclude='./.git' \
    --exclude='./volumes/db/data' \
    --exclude='./volumes/storage' \
    .
tar --file "$run_dir/supabase-config.tar" --list >/dev/null
tar --acls --xattrs --numeric-owner --file "$run_dir/mvp-config.tar" --create \
    --directory "$MVP_CONFIG_DIR" .
tar --file "$run_dir/mvp-config.tar" --list >/dev/null

(
    cd "$run_dir"
    sha256sum postgres-globals.sql postgres-roles.txt postgres.dump _supabase.dump \
        db-config.tar storage.tar supabase-config.tar mvp-config.tar > payload.sha256
    printf '%s\n' \
        "schema=2" \
        "created_at_utc=$timestamp" \
        "supabase_upstream_sha=$SUPABASE_UPSTREAM_SHA" \
        "rpo_target_hours=24" \
        "consistency=write-services-stopped" \
        "contents=postgres-custom-dumps,role-inventory,postgres-custom-config,storage,supabase-config,mvp-config" > metadata.txt
)
tar --file "$bundle" --create --directory "$run_dir" \
    postgres-globals.sql postgres-roles.txt postgres.dump _supabase.dump \
    db-config.tar storage.tar supabase-config.tar mvp-config.tar payload.sha256 metadata.txt

age --recipients-file "$AGE_RECIPIENT_FILE" --output "$encrypted" "$bundle"
[ -s "$encrypted" ] || { printf '%s\n' "encrypted backup is empty" >&2; exit 65; }
(
    cd "$BACKUP_STAGING_DIR"
    sha256sum "$(basename -- "$encrypted")" > "$(basename -- "$encrypted_checksum")"
)

remote_base=${BACKUP_REMOTE%/}
rclone --config "$RCLONE_CONFIG" copyto "$encrypted" \
    "$remote_base/$(basename -- "$encrypted")" --immutable
rclone --config "$RCLONE_CONFIG" copyto "$encrypted_checksum" \
    "$remote_base/$(basename -- "$encrypted_checksum")" --immutable

remote_hash=$(rclone --config "$RCLONE_CONFIG" cat \
    "$remote_base/$(basename -- "$encrypted_checksum")" | awk '{print $1}')
local_hash=$(sha256sum "$encrypted" | awk '{print $1}')
[ "$remote_hash" = "$local_hash" ] || {
    printf '%s\n' "offsite encrypted-backup checksum verification failed" >&2
    exit 65
}

state_dir=${BACKUP_STATE_DIR:-/var/lib/defense-tracker-backup}
python3 "$state_tool" prepare "$state_dir"
state_tmp="$state_dir/.last-success.tmp"
printf '%s\n' \
    "schema=1" \
    "completed_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "backup_file=$(basename -- "$encrypted")" \
    "sha256=$local_hash" > "$state_tmp"
chmod 0600 "$state_tmp"
mv -f "$state_tmp" "$state_dir/last-success"

printf '%s\n' "[BACKUP] Encrypted Postgres, Storage and configuration backup uploaded and checksum-verified."
printf '%s\n' "[BACKUP] Retention is controlled at the offsite target; this script never deletes remote backups."
