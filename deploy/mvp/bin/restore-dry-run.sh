#!/bin/sh
set -eu
umask 077
TRUSTED_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
readonly TRUSTED_PATH
PATH=$TRUSTED_PATH
export PATH

usage() {
    printf '%s\n' "usage: $0 ENCRYPTED_BACKUP AGE_IDENTITY_FILE [CHECKSUM_FILE]" >&2
    exit 64
}
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage

encrypted_backup=$1
identity_file=$2
checksum_file=${3:-$encrypted_backup.sha256}
[ -r "$encrypted_backup" ] && [ -r "$identity_file" ] && [ -r "$checksum_file" ] || {
    printf '%s\n' "backup, identity or checksum file is unreadable" >&2
    exit 66
}

for command_name in docker age tar sha256sum python3 grep awk git stat readlink dirname; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf '%s\n' "required preinstalled restore command is missing: $command_name" >&2
        exit 69
    }
done

assert_root_controlled_path() {
    target=$1
    label=$2
    [ -e "$target" ] || {
        printf '%s\n' "$label is missing" >&2
        exit 66
    }
    resolved=$(readlink -f -- "$target")
    [ "$resolved" = "$target" ] || {
        printf '%s\n' "$label must be an absolute path without symlinks" >&2
        exit 77
    }
    current=$resolved
    while :; do
        owner_uid=$(stat -c '%u' -- "$current")
        permissions=$(stat -c '%a' -- "$current")
        group_digit=$((permissions / 10 % 10))
        other_digit=$((permissions % 10))
        [ "$owner_uid" = 0 ] || {
            printf '%s\n' "$label path is not root-owned" >&2
            exit 77
        }
        case "$group_digit:$other_digit" in
            2:*|3:*|6:*|7:*|*:2|*:3|*:6|*:7)
                printf '%s\n' "$label path is group- or other-writable" >&2
                exit 77
                ;;
        esac
        [ "$current" = / ] && break
        current=$(dirname -- "$current")
    done
}

collector_release_root=${DEFENSE_TRACKER_RELEASE_ROOT:?DEFENSE_TRACKER_RELEASE_ROOT is required}
collector_release_sha=${DEFENSE_TRACKER_RELEASE_SHA:?DEFENSE_TRACKER_RELEASE_SHA is required}
readonly collector_release_root collector_release_sha
config_file=${MVP_PRODUCTION_ENV:-/etc/defense-tracker/production.env}
assert_root_controlled_path "$config_file" "production configuration"
set -a
# shellcheck disable=SC1090
. "$config_file"
set +a
PATH=$TRUSTED_PATH
export PATH
: "${SUPABASE_STACK_DIR:?SUPABASE_STACK_DIR is required}"
: "${SUPABASE_UPSTREAM_SHA:?SUPABASE_UPSTREAM_SHA is required}"
: "${SUPABASE_OVERRIDE_FILE:?SUPABASE_OVERRIDE_FILE is required}"
: "${BACKUP_STAGING_DIR:?BACKUP_STAGING_DIR is required}"

printf '%s' "$collector_release_sha" | grep -Eq '^[0-9a-f]{40}$' || {
    printf '%s\n' "collector release SHA is invalid" >&2
    exit 65
}
assert_root_controlled_path "$collector_release_root" "collector release checkout"
release_git_directory=$(git -C "$collector_release_root" rev-parse --absolute-git-dir 2>/dev/null || true)
[ -n "$release_git_directory" ] || {
    printf '%s\n' "collector release Git directory is unavailable" >&2
    exit 65
}
assert_root_controlled_path "$release_git_directory" "collector release Git directory"
release_head=$(git -C "$collector_release_root" rev-parse --verify HEAD 2>/dev/null || true)
[ "$release_head" = "$collector_release_sha" ] || {
    printf '%s\n' "collector release checkout differs from the requested release" >&2
    exit 65
}
release_worktree_status=$(git -C "$collector_release_root" status \
    --porcelain --untracked-files=all --ignore-submodules=none)
[ -z "$release_worktree_status" ] || {
    printf '%s\n' "collector release checkout contains modified or untracked files" >&2
    exit 77
}
trusted_override_file="$collector_release_root/deploy/mvp/supabase.production.override.yml"
configured_override_file=$(readlink -f -- "$SUPABASE_OVERRIDE_FILE")
[ "$configured_override_file" = "$trusted_override_file" ] || {
    printf '%s\n' "Supabase override is not the exact release file" >&2
    exit 77
}
git -C "$collector_release_root" ls-files --error-unmatch \
    deploy/mvp/supabase.production.override.yml >/dev/null 2>&1 || {
        printf '%s\n' "Supabase override is not tracked by the release commit" >&2
        exit 77
    }
assert_root_controlled_path "$trusted_override_file" "Supabase override file"
SUPABASE_OVERRIDE_FILE=$trusted_override_file

backup_staging_parent=$(dirname -- "$BACKUP_STAGING_DIR")
assert_root_controlled_path "$backup_staging_parent" "backup staging parent"
mkdir -p "$BACKUP_STAGING_DIR"
assert_root_controlled_path "$BACKUP_STAGING_DIR" "backup staging directory"

expected_hash=$(awk 'NR == 1 {print $1}' "$checksum_file")
actual_hash=$(sha256sum "$encrypted_backup" | awk '{print $1}')
[ -n "$expected_hash" ] && [ "$expected_hash" = "$actual_hash" ] || {
    printf '%s\n' "encrypted backup checksum does not match" >&2
    exit 65
}

work_dir=$(mktemp -d "$BACKUP_STAGING_DIR/restore-dry-run-XXXXXX")
bundle="$work_dir/bundle.tar"
payload="$work_dir/payload"
container_name="defense-restore-check-$(date -u +%Y%m%d%H%M%S)-$$"
container_started=false
volume_name="defense_restore_check_$(date -u +%Y%m%d%H%M%S)_$$"
volume_created=false
config_volume_name="defense_restore_config_check_$(date -u +%Y%m%d%H%M%S)_$$"
config_volume_created=false

cleanup() {
    if [ "$container_started" = true ]; then
        docker rm --force "$container_name" >/dev/null 2>&1 || true
    fi
    if [ "$volume_created" = true ]; then
        docker volume inspect "$volume_name" >/dev/null 2>&1 || true
        docker volume rm "$volume_name" >/dev/null 2>&1 || true
    fi
    if [ "$config_volume_created" = true ]; then
        docker volume inspect "$config_volume_name" >/dev/null 2>&1 || true
        docker volume rm "$config_volume_name" >/dev/null 2>&1 || true
    fi
    if [ -d "$work_dir" ]; then
        case "$work_dir" in "$BACKUP_STAGING_DIR"/restore-dry-run-*) find "$work_dir" -depth -delete ;; esac
    fi
}
trap cleanup EXIT HUP INT TERM

assert_safe_tar() {
    python3 - "$1" <<'PY'
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
with tarfile.open(archive, "r:*") as handle:
    for member in handle.getmembers():
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit("archive contains an unsafe path")
        if member.ischr() or member.isblk() or member.isfifo():
            raise SystemExit("archive contains a device or FIFO")
        if member.issym() or member.islnk():
            raise SystemExit("archive links are not allowed")
PY
}

age --decrypt --identity "$identity_file" --output "$bundle" "$encrypted_backup"
assert_safe_tar "$bundle"
tar --file "$bundle" --list >/dev/null
mkdir -m 0700 "$payload"
tar --file "$bundle" --extract --directory "$payload"
(
    cd "$payload"
    sha256sum --check --status payload.sha256
)
for postgres_payload in postgres-globals.sql postgres-roles.txt postgres.dump _supabase.dump; do
    [ -s "$payload/$postgres_payload" ] || {
        printf '%s\n' "decrypted Postgres payload is incomplete" >&2
        exit 65
    }
done
[ -s "$payload/metadata.txt" ] || {
    printf '%s\n' "decrypted backup metadata is missing" >&2
    exit 65
}
grep -q 'CREATE ROLE' "$payload/postgres-globals.sql" || {
    printf '%s\n' "global role inventory is invalid" >&2
    exit 65
}
globals_existing="$work_dir/postgres-globals-existing.sql"
awk '!/^CREATE ROLE / { print }' "$payload/postgres-globals.sql" > "$globals_existing"
[ -s "$globals_existing" ] && ! grep -Eq '^CREATE ROLE ' "$globals_existing" || {
    printf '%s\n' "unable to remove duplicate role creation from global restore" >&2
    exit 65
}
tar --file "$payload/storage.tar" --list >/dev/null
tar --file "$payload/db-config.tar" --list >/dev/null
tar --file "$payload/supabase-config.tar" --list >/dev/null
tar --file "$payload/mvp-config.tar" --list >/dev/null
assert_safe_tar "$payload/storage.tar"
assert_safe_tar "$payload/db-config.tar"
assert_safe_tar "$payload/supabase-config.tar"
assert_safe_tar "$payload/mvp-config.tar"
mkdir -m 0700 "$work_dir/storage-check" "$work_dir/supabase-config-check" "$work_dir/mvp-config-check"
tar --file "$payload/storage.tar" --extract --directory "$work_dir/storage-check"
tar --file "$payload/supabase-config.tar" --extract --directory "$work_dir/supabase-config-check"
tar --file "$payload/mvp-config.tar" --extract --directory "$work_dir/mvp-config-check"
[ "$(find "$work_dir/storage-check" -mindepth 1 | wc -l)" -gt 0 ] || {
    printf '%s\n' "Storage archive extracted no entries" >&2
    exit 65
}
[ "$(find "$work_dir/supabase-config-check" -mindepth 1 | wc -l)" -gt 0 ] || {
    printf '%s\n' "Supabase configuration archive extracted no entries" >&2
    exit 65
}
[ "$(find "$work_dir/mvp-config-check" -mindepth 1 | wc -l)" -gt 0 ] || {
    printf '%s\n' "configuration archive extracted no entries" >&2
    exit 65
}
[ -s "$work_dir/supabase-config-check/.env" ] || {
    printf '%s\n' "backed-up Supabase environment is missing" >&2
    exit 65
}
restore_stack_env="$work_dir/supabase-config-check/.env"

stack_compose="$SUPABASE_STACK_DIR/docker-compose.yml"
stack_env="$SUPABASE_STACK_DIR/.env"
[ -f "$stack_compose" ] && [ -f "$stack_env" ] && [ -f "$SUPABASE_OVERRIDE_FILE" ] || {
    printf '%s\n' "official Supabase Compose checkout is incomplete" >&2
    exit 66
}
assert_root_controlled_path "$SUPABASE_STACK_DIR" "Supabase checkout"
assert_root_controlled_path "$stack_compose" "Supabase Compose file"
assert_root_controlled_path "$stack_env" "Supabase environment file"
assert_root_controlled_path "$SUPABASE_OVERRIDE_FILE" "Supabase override file"
metadata_sha_count=$(grep -Ec '^supabase_upstream_sha=[0-9a-f]{40}$' "$payload/metadata.txt" || true)
[ "$metadata_sha_count" = 1 ] || {
    printf '%s\n' "backup does not identify one pinned Supabase commit" >&2
    exit 65
}
backup_supabase_sha=$(awk -F= '$1 == "supabase_upstream_sha" { print $2 }' "$payload/metadata.txt")
actual_supabase_sha=$(git -C "$SUPABASE_STACK_DIR" rev-parse HEAD 2>/dev/null || true)
[ "$backup_supabase_sha" = "$SUPABASE_UPSTREAM_SHA" ] && \
    [ "$actual_supabase_sha" = "$SUPABASE_UPSTREAM_SHA" ] || {
        printf '%s\n' "restore image checkout differs from the backup Supabase commit" >&2
        exit 65
    }
supabase_worktree_status=$(git -C "$SUPABASE_STACK_DIR" status \
    --porcelain --untracked-files=all --ignore-submodules=none)
[ -z "$supabase_worktree_status" ] || {
    printf '%s\n' "restore image checkout contains modified or untracked files" >&2
    exit 77
}
for init_file in \
    realtime.sql webhooks.sql roles.sql jwt.sql _supabase.sql logs.sql pooler.sql; do
    [ -f "$SUPABASE_STACK_DIR/volumes/db/$init_file" ] || {
        printf '%s\n' "pinned Supabase DB initialization source is incomplete" >&2
        exit 66
    }
    assert_root_controlled_path "$SUPABASE_STACK_DIR/volumes/db/$init_file" \
        "Supabase DB initialization source"
done
db_image=$(
    cd "$SUPABASE_STACK_DIR"
    docker compose --env-file "$stack_env" --file "$stack_compose" \
        --file "$SUPABASE_OVERRIDE_FILE" config --format json |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["db"]["image"])'
)
[ -n "$db_image" ] || { printf '%s\n' "unable to resolve pinned Supabase DB image" >&2; exit 65; }
docker image inspect "$db_image" >/dev/null 2>&1 || {
    printf '%s\n' "pinned DB image is not present locally; dry-run will not pull implicitly" >&2
    exit 69
}
db_image_id=$(docker image inspect --format '{{.Id}}' "$db_image")
[ "${#db_image_id}" -eq 71 ] && \
    printf '%s' "$db_image_id" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
        printf '%s\n' "pinned DB image did not resolve to an immutable image ID" >&2
        exit 65
    }

docker volume create "$volume_name" >/dev/null
volume_created=true
docker volume create "$config_volume_name" >/dev/null
config_volume_created=true
docker run --rm --pull never --network none --entrypoint /bin/sh \
    --volume "$config_volume_name:/target" \
    --volume "$payload/db-config.tar:/backup/db-config.tar:ro" \
    "$db_image_id" -c 'tar --extract --file /backup/db-config.tar --directory /target'
docker run --detach --pull never --name "$container_name" \
    --network none \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --tmpfs /run/postgresql:rw,noexec,nosuid,nodev,size=16m \
    --security-opt no-new-privileges:true \
    --volume "$volume_name:/var/lib/postgresql/data" \
    --volume "$config_volume_name:/etc/postgresql-custom" \
    --volume "$SUPABASE_STACK_DIR/volumes/db/realtime.sql:/docker-entrypoint-initdb.d/migrations/99-realtime.sql:ro" \
    --volume "$SUPABASE_STACK_DIR/volumes/db/webhooks.sql:/docker-entrypoint-initdb.d/init-scripts/98-webhooks.sql:ro" \
    --volume "$SUPABASE_STACK_DIR/volumes/db/roles.sql:/docker-entrypoint-initdb.d/init-scripts/99-roles.sql:ro" \
    --volume "$SUPABASE_STACK_DIR/volumes/db/jwt.sql:/docker-entrypoint-initdb.d/init-scripts/99-jwt.sql:ro" \
    --volume "$SUPABASE_STACK_DIR/volumes/db/_supabase.sql:/docker-entrypoint-initdb.d/migrations/97-_supabase.sql:ro" \
    --volume "$SUPABASE_STACK_DIR/volumes/db/logs.sql:/docker-entrypoint-initdb.d/migrations/99-logs.sql:ro" \
    --volume "$SUPABASE_STACK_DIR/volumes/db/pooler.sql:/docker-entrypoint-initdb.d/migrations/99-pooler.sql:ro" \
    --env-file "$restore_stack_env" \
    --env POSTGRES_HOST_AUTH_METHOD=trust \
    "$db_image_id" >/dev/null
container_started=true

ready=false
attempt=0
while [ "$attempt" -lt 60 ]; do
    if docker exec "$container_name" pg_isready --username postgres >/dev/null 2>&1; then
        ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
[ "$ready" = true ] || { printf '%s\n' "isolated restore database did not become ready" >&2; exit 70; }

# The pinned Supabase image/init scripts already create the platform roles.
# Replaying pg_dumpall CREATE ROLE statements would fail on those same names;
# validate the inventory instead, then restore only custom-format databases.
docker cp "$payload/postgres-roles.txt" "$container_name:/tmp/postgres-roles.txt"
if ! docker exec --interactive "$container_name" \
    psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
    > "$work_dir/restore.log" 2>&1 <<'SQL'
create temp table expected_restore_roles(role_name text primary key);
\copy expected_restore_roles(role_name) from '/tmp/postgres-roles.txt'
do $$
begin
    if exists (
        select 1 from expected_restore_roles e
        left join pg_catalog.pg_roles r on r.rolname = e.role_name
        where r.rolname is null
    ) then
        raise exception 'restore image is missing a source role';
    end if;
end;
$$;
SQL
then
    printf '%s\n' "pinned restore image does not provide the source role inventory" >&2
    exit 65
fi

if ! docker exec --interactive "$container_name" \
    psql --username postgres --dbname postgres --set ON_ERROR_STOP=1 \
    < "$globals_existing" >> "$work_dir/restore.log" 2>&1
then
    printf '%s\n' "non-creating global role settings restore failed" >&2
    exit 65
fi

docker exec --interactive "$container_name" \
    pg_restore --exit-on-error --clean --if-exists \
        --username postgres --dbname postgres \
    < "$payload/postgres.dump" >> "$work_dir/restore.log" 2>&1 || {
        printf '%s\n' "postgres database restore failed inside the isolated container" >&2
        exit 65
    }
docker exec --interactive "$container_name" \
    pg_restore --exit-on-error --clean --if-exists \
        --username postgres --dbname _supabase \
    < "$payload/_supabase.dump" >> "$work_dir/restore.log" 2>&1 || {
        printf '%s\n' "_supabase database restore failed inside the isolated container" >&2
        exit 65
    }
database_count=$(docker exec "$container_name" psql --username postgres --tuples-only --no-align \
    --command "select count(*) from pg_database where datistemplate = false;")
[ "$database_count" = 2 ] || { printf '%s\n' "restored database validation failed" >&2; exit 65; }
restored_contract=$(docker exec "$container_name" psql --username postgres --dbname postgres \
    --tuples-only --no-align --set ON_ERROR_STOP=1 --command \
    "select (to_regclass('public.organizations') is not null and to_regprocedure('public.bind_device_session(uuid,uuid)') is not null and to_regprocedure('public.put_user_ai_credential(jsonb)') is not null)::text;")
[ "$restored_contract" = true ] || {
    printf '%s\n' "restored MVP schema contract is incomplete" >&2
    exit 65
}

printf '%s\n' "[RESTORE] Encrypted checksum, decryption and all payload hashes passed."
printf '%s\n' "[RESTORE] Both databases restored without replaying duplicate roles in a temporary --network none container."
printf '%s\n' "[RESTORE] Storage/config archives were read-tested against the same maintenance-window payload."
printf '%s\n' "[RESTORE] Production data and containers were not modified."
printf '{"schema":1,"measurement_kind":"database_count","records_expected":2,"records_restored":%s}\n' \
    "$database_count"
