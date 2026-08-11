#!/bin/sh
set -eu
umask 077

usage() {
    printf '%s\n' "usage: $0 [--prepare-functions] EXPECTED_GIT_SHA [PRODUCTION_ENV]" >&2
    exit 64
}

mode=install
if [ "${1:-}" = "--prepare-functions" ]; then
    mode=prepare
    shift
fi
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
expected_release_sha=$1
config_file=${2:-/etc/defense-tracker/production.env}
printf '%s' "$expected_release_sha" | grep -Eq '^[0-9a-f]{40}$' || {
    printf '%s\n' "expected release SHA must be 40 lowercase hexadecimal characters" >&2
    exit 64
}
[ -f "$config_file" ] || { printf '%s\n' "production env file is missing" >&2; exit 66; }
set -a
# shellcheck disable=SC1090
. "$config_file"
set +a

: "${SUPABASE_STACK_DIR:?SUPABASE_STACK_DIR is required}"
: "${SUPABASE_UPSTREAM_SHA:?SUPABASE_UPSTREAM_SHA is required}"
: "${SUPABASE_OVERRIDE_FILE:?SUPABASE_OVERRIDE_FILE is required}"
: "${SUPABASE_FUNCTIONS_DEPLOY_DIR:?SUPABASE_FUNCTIONS_DEPLOY_DIR is required}"
: "${MVP_RELEASE_STATE_DIR:?MVP_RELEASE_STATE_DIR is required}"

for command_name in docker sha256sum find sort awk cp chmod mkdir ln mv flock grep git python3 tr; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf '%s\n' "required application installer command is missing: $command_name" >&2
        exit 69
    }
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
actual_release_sha=$(git -C "$project_root" rev-parse HEAD 2>/dev/null || true)
[ "$actual_release_sha" = "$expected_release_sha" ] || {
    printf '%s\n' "project checkout HEAD does not match expected release SHA" >&2
    exit 65
}
[ -z "$(git -C "$project_root" status --porcelain --untracked-files=all)" ] || {
    printf '%s\n' "project checkout must be clean before Supabase installation" >&2
    exit 65
}

metadata_tool="$script_dir/backend-release-metadata.py"
[ -f "$metadata_tool" ] || { printf '%s\n' "backend release metadata tool is missing" >&2; exit 66; }
backend_manifest=$(python3 "$metadata_tool" --repo "$project_root" \
    --git-sha "$expected_release_sha" --field source_manifest_sha256)
backend_wire=$(python3 "$metadata_tool" --repo "$project_root" \
    --git-sha "$expected_release_sha" --field wire_compatibility)
backend_policy=$(python3 "$metadata_tool" --repo "$project_root" \
    --git-sha "$expected_release_sha" --field migration_policy)

migration_dir="$project_root/supabase/migrations"
base="$SUPABASE_STACK_DIR/docker-compose.yml"
upstream_env="$SUPABASE_STACK_DIR/.env"
main_source="$SUPABASE_STACK_DIR/volumes/functions/main"
for required_path in \
    "$base" "$upstream_env" "$SUPABASE_OVERRIDE_FILE" \
    "$main_source/index.ts" \
    "$project_root/supabase/migrations/202608100026_mvp_idempotent_device_registration.sql" \
    "$project_root/supabase/functions/access-applications/index.ts" \
    "$project_root/supabase/functions/invite-member/index.ts"; do
    [ -e "$required_path" ] || {
        printf '%s\n' "required migration/function deployment source is missing" >&2
        exit 66
    }
done
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

case "$SUPABASE_FUNCTIONS_DEPLOY_DIR" in
    /*/current) ;;
    *) printf '%s\n' "SUPABASE_FUNCTIONS_DEPLOY_DIR must be an absolute path ending in /current" >&2; exit 64 ;;
esac
deploy_root=$(dirname -- "$SUPABASE_FUNCTIONS_DEPLOY_DIR")
case "$deploy_root" in
    /|/bin|/boot|/dev|/etc|/home|/opt|/root|/run|/srv|/usr|/var)
        printf '%s\n' "function deployment root is too broad" >&2
        exit 64
        ;;
esac

case "$MVP_RELEASE_STATE_DIR" in
    /*) ;;
    *) printf '%s\n' "MVP_RELEASE_STATE_DIR must be absolute" >&2; exit 64 ;;
esac
mkdir -p "$MVP_RELEASE_STATE_DIR"
chmod 0700 "$MVP_RELEASE_STATE_DIR"
exec 8>"$MVP_RELEASE_STATE_DIR/.supabase-app.lock"
flock -n 8 || { printf '%s\n' "another Supabase application install is active" >&2; exit 75; }

hash_tree() {
    tree_root=$1
    tree_label=$2
    LC_ALL=C find "$tree_root" -type f -print | LC_ALL=C sort | while IFS= read -r source_file; do
        relative=${source_file#"$tree_root"/}
        file_hash=$(sha256sum "$source_file" | awk '{print $1}')
        printf '%s  %s/%s\n' "$file_hash" "$tree_label" "$relative"
    done
}

function_digest=$(
    {
        hash_tree "$main_source" main
        hash_tree "$project_root/supabase/functions/access-applications" access-applications
        hash_tree "$project_root/supabase/functions/invite-member" invite-member
    } | LC_ALL=C sort | sha256sum | awk '{print $1}'
)
printf '%s' "$function_digest" | grep -Eq '^[0-9a-f]{64}$' || {
    printf '%s\n' "unable to calculate function source digest" >&2
    exit 65
}

mkdir -p "$deploy_root/releases"
chmod 0700 "$deploy_root" "$deploy_root/releases"
release_dir="$deploy_root/releases/$expected_release_sha-$function_digest"
if [ -e "$release_dir" ]; then
    [ -d "$release_dir" ] || { printf '%s\n' "existing function release is incomplete" >&2; exit 65; }
    for metadata_file in \
        .source.sha256 .project-release.sha .project-manifest.sha256 \
        .backend-wire .migration-policy .supabase-upstream.sha; do
        [ -s "$release_dir/$metadata_file" ] || {
            printf '%s\n' "existing function release metadata is incomplete" >&2
            exit 65
        }
    done
    [ "$(tr -d '\r\n' < "$release_dir/.source.sha256")" = "$function_digest" ] && \
        [ "$(tr -d '\r\n' < "$release_dir/.project-release.sha")" = "$expected_release_sha" ] && \
        [ "$(tr -d '\r\n' < "$release_dir/.project-manifest.sha256")" = "$backend_manifest" ] && \
        [ "$(tr -d '\r\n' < "$release_dir/.backend-wire")" = "$backend_wire" ] && \
        [ "$(tr -d '\r\n' < "$release_dir/.migration-policy")" = "$backend_policy" ] && \
        [ "$(tr -d '\r\n' < "$release_dir/.supabase-upstream.sha")" = "$SUPABASE_UPSTREAM_SHA" ] || {
        printf '%s\n' "existing function release metadata does not match the exact release" >&2
        exit 65
    }
else
    staging="$deploy_root/.staging-$function_digest-$$"
    [ ! -e "$staging" ] || { printf '%s\n' "function staging path already exists" >&2; exit 65; }
    mkdir -m 0700 "$staging"
    cp -R "$main_source" "$staging/main"
    cp -R "$project_root/supabase/functions/access-applications" "$staging/access-applications"
    cp -R "$project_root/supabase/functions/invite-member" "$staging/invite-member"
    printf '%s\n' "$function_digest" > "$staging/.source.sha256"
    printf '%s\n' "$expected_release_sha" > "$staging/.project-release.sha"
    printf '%s\n' "$backend_manifest" > "$staging/.project-manifest.sha256"
    printf '%s\n' "$backend_wire" > "$staging/.backend-wire"
    printf '%s\n' "$backend_policy" > "$staging/.migration-policy"
    printf '%s\n' "$SUPABASE_UPSTREAM_SHA" > "$staging/.supabase-upstream.sha"
    find "$staging" -type d -exec chmod 0755 {} +
    find "$staging" -type f -exec chmod 0644 {} +
    mv "$staging" "$release_dir"
fi

new_link="$deploy_root/.current-$function_digest-$$"
ln -s "releases/$expected_release_sha-$function_digest" "$new_link"
if [ -e "$SUPABASE_FUNCTIONS_DEPLOY_DIR" ] && [ ! -L "$SUPABASE_FUNCTIONS_DEPLOY_DIR" ]; then
    printf '%s\n' "function deployment current path must be a managed symlink" >&2
    exit 65
fi
mv -Tf "$new_link" "$SUPABASE_FUNCTIONS_DEPLOY_DIR"
printf '%s\n' "[SUPABASE-APP] Prepared immutable Edge Function source: $function_digest"

[ "$mode" = install ] || exit 0

compose() {
    docker compose --env-file "$upstream_env" --file "$base" \
        --file "$SUPABASE_OVERRIDE_FILE" "$@"
}
compose ps --status running --services | grep -qx db || {
    printf '%s\n' "Supabase database must be running before migrations are installed" >&2
    exit 70
}
psql_db() {
    compose exec -T db psql --username postgres --dbname postgres \
        --set ON_ERROR_STOP=1 "$@"
}

psql_db --quiet <<'SQL'
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
create table if not exists private.schema_migrations (
    name text primary key check (name ~ '^[0-9]{12}_[a-z0-9_]+[.]sql$'),
    digest text not null check (digest ~ '^[0-9a-f]{64}$'),
    status text not null check (status in ('applying','applied','failed')),
    started_at timestamptz not null default timezone('utc', now()),
    applied_at timestamptz,
    error_code text
);
create table if not exists private.mvp_backend_releases (
    release_sha text primary key check (release_sha ~ '^[0-9a-f]{40}$'),
    source_manifest_sha256 text not null check (source_manifest_sha256 ~ '^[0-9a-f]{64}$'),
    wire_compatibility text not null check (wire_compatibility ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    migration_policy text not null check (migration_policy = 'expand-contract'),
    function_digest text not null check (function_digest ~ '^[0-9a-f]{64}$'),
    supabase_upstream_sha text not null check (supabase_upstream_sha ~ '^[0-9a-f]{40}$'),
    status text not null check (status in ('installing','active','superseded','failed')),
    started_at timestamptz not null default timezone('utc', now()),
    activated_at timestamptz,
    failed_at timestamptz,
    error_code text
);
create unique index if not exists mvp_backend_releases_one_active
    on private.mvp_backend_releases ((status)) where status = 'active';
revoke all on table private.schema_migrations from public, anon, authenticated, service_role;
revoke all on table private.mvp_backend_releases from public, anon, authenticated, service_role;
SQL

expected_prefix="$backend_manifest:$backend_wire:$backend_policy:$function_digest:$SUPABASE_UPSTREAM_SHA"
backend_record=$(psql_db --tuples-only --no-align \
    --set "release_sha=$expected_release_sha" --command \
    "select source_manifest_sha256 || ':' || wire_compatibility || ':' || migration_policy || ':' || function_digest || ':' || supabase_upstream_sha || ':' || status from private.mvp_backend_releases where release_sha = :'release_sha';")
backend_install_pending=false
case "$backend_record" in
    "$expected_prefix:active") ;;
    '')
        psql_db --quiet \
            --set "release_sha=$expected_release_sha" \
            --set "source_manifest=$backend_manifest" \
            --set "wire=$backend_wire" \
            --set "policy=$backend_policy" \
            --set "function_digest=$function_digest" \
            --set "upstream_sha=$SUPABASE_UPSTREAM_SHA" <<'SQL'
insert into private.mvp_backend_releases(
    release_sha,source_manifest_sha256,wire_compatibility,migration_policy,
    function_digest,supabase_upstream_sha,status
) values (
    :'release_sha',:'source_manifest',:'wire',:'policy',
    :'function_digest',:'upstream_sha','installing'
);
SQL
        backend_install_pending=true
        ;;
    "$expected_prefix:installing"|"$expected_prefix:failed")
        printf '%s\n' "backend release has an unresolved previous installation attempt" >&2
        exit 65
        ;;
    "$expected_prefix:superseded")
        printf '%s\n' "a superseded backend release cannot be made active by Portal rollback" >&2
        exit 65
        ;;
    *)
        printf '%s\n' "backend release metadata changed after registration" >&2
        exit 65
        ;;
esac

mark_backend_failed() {
    psql_db --quiet --set "release_sha=$expected_release_sha" <<'SQL' || true
update private.mvp_backend_releases
   set status = 'failed', failed_at = timezone('utc', now()),
       error_code = 'installer_failed'
 where release_sha = :'release_sha' and status = 'installing';
SQL
}
on_exit() {
    exit_status=$1
    trap - 0
    if [ "$exit_status" -ne 0 ] && [ "$backend_install_pending" = true ]; then
        mark_backend_failed
    fi
    exit "$exit_status"
}
trap 'on_exit "$?"' 0

for migration in "$migration_dir"/*.sql; do
    [ -f "$migration" ] || { printf '%s\n' "no Supabase migrations were found" >&2; exit 66; }
    migration_name=$(basename -- "$migration")
    migration_digest=$(sha256sum "$migration" | awk '{print $1}')
    record=$(psql_db --tuples-only --no-align \
        --set "migration_name=$migration_name" \
        --command "select digest || ':' || status from private.schema_migrations where name = :'migration_name';")
    case "$record" in
        "$migration_digest:applied") continue ;;
        '') ;;
        "$migration_digest:"*)
            printf '%s\n' "migration has an unresolved previous installation attempt: $migration_name" >&2
            exit 65
            ;;
        *)
            printf '%s\n' "migration digest changed after registration: $migration_name" >&2
            exit 65
            ;;
    esac

    if [ "$migration_name" = "202608090021_mvp_device_sessions.sql" ]; then
        existing_devices=$(psql_db --tuples-only --no-align --command \
            "select case when to_regclass('public.devices') is null then 0 else (select count(*) from public.devices) end;")
        [ "$existing_devices" = 0 ] || {
            printf '%s\n' "MVP device-session migration requires an empty devices table" >&2
            exit 65
        }
    fi

    psql_db --quiet --set "migration_name=$migration_name" \
        --set "migration_digest=$migration_digest" <<'SQL'
insert into private.schema_migrations(name,digest,status)
values (:'migration_name', :'migration_digest', 'applying');
SQL
    if ! psql_db < "$migration"; then
        psql_db --quiet --set "migration_name=$migration_name" <<'SQL' || true
update private.schema_migrations
   set status = 'failed', error_code = 'psql_failed'
 where name = :'migration_name' and status = 'applying';
SQL
        printf '%s\n' "Supabase migration failed: $migration_name" >&2
        exit 65
    fi
    psql_db --quiet --set "migration_name=$migration_name" <<'SQL'
update private.schema_migrations
   set status = 'applied', applied_at = timezone('utc', now()), error_code = null
 where name = :'migration_name' and status = 'applying';
SQL
done

# Recreate rather than restart: Docker resolves the immutable `current`
# symlink when the bind mount is created.
compose up --detach --no-deps --force-recreate --wait --wait-timeout 180 functions
if [ "$backend_install_pending" = true ]; then
    MVP_VERIFY_BACKEND_STATUS=installing \
        "$script_dir/verify-supabase-app.sh" "$expected_release_sha" "$config_file"
    psql_db --quiet --set "release_sha=$expected_release_sha" <<'SQL'
begin;
update private.mvp_backend_releases
   set status = 'superseded'
 where status = 'active' and release_sha <> :'release_sha';
update private.mvp_backend_releases
   set status = 'active', activated_at = timezone('utc', now()),
       failed_at = null, error_code = null
 where release_sha = :'release_sha' and status = 'installing';
commit;
SQL
    backend_install_pending=false
fi

write_backend_state() {
    state_name=$1
    state_value=$2
    printf '%s\n' "$state_value" > "$MVP_RELEASE_STATE_DIR/.backend.$state_name.tmp-$$"
    mv -f "$MVP_RELEASE_STATE_DIR/.backend.$state_name.tmp-$$" \
        "$MVP_RELEASE_STATE_DIR/backend.$state_name"
}
write_backend_state sha "$expected_release_sha"
write_backend_state manifest "$backend_manifest"
write_backend_state wire "$backend_wire"
write_backend_state policy "$backend_policy"
write_backend_state functions "$function_digest"
write_backend_state upstream "$SUPABASE_UPSTREAM_SHA"
chmod 0600 "$MVP_RELEASE_STATE_DIR"/backend.*

"$script_dir/verify-supabase-app.sh" "$expected_release_sha" "$config_file"
printf '%s\n' "[SUPABASE-APP] All hash-registered migrations through the exact release and both Edge Functions are installed."
printf '%s\n' "[SUPABASE-APP] Active backend Git SHA: $expected_release_sha"
printf '%s\n' "[SUPABASE-APP] Historical function releases were retained; no deployment source was deleted."
