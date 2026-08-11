#!/bin/sh
set -eu

usage() {
    printf '%s\n' "usage: $0 EXPECTED_GIT_SHA [PRODUCTION_ENV]" >&2
    exit 64
}
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

expected_backend_status=${MVP_VERIFY_BACKEND_STATUS:-active}
case "$expected_backend_status" in
    active|installing) ;;
    *) printf '%s\n' "unsupported backend verification status" >&2; exit 64 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
actual_release_sha=$(git -C "$project_root" rev-parse HEAD 2>/dev/null || true)
[ "$actual_release_sha" = "$expected_release_sha" ] || {
    printf '%s\n' "project checkout HEAD does not match expected release SHA" >&2
    exit 65
}
[ -z "$(git -C "$project_root" status --porcelain --untracked-files=all)" ] || {
    printf '%s\n' "project checkout must be clean during backend verification" >&2
    exit 65
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

metadata_tool="$script_dir/backend-release-metadata.py"
backend_manifest=$(python3 "$metadata_tool" --repo "$project_root" \
    --git-sha "$expected_release_sha" --field source_manifest_sha256)
backend_wire=$(python3 "$metadata_tool" --repo "$project_root" \
    --git-sha "$expected_release_sha" --field wire_compatibility)
backend_policy=$(python3 "$metadata_tool" --repo "$project_root" \
    --git-sha "$expected_release_sha" --field migration_policy)

migration_dir="$project_root/supabase/migrations"
base="$SUPABASE_STACK_DIR/docker-compose.yml"
upstream_env="$SUPABASE_STACK_DIR/.env"
compose() {
    docker compose --env-file "$upstream_env" --file "$base" \
        --file "$SUPABASE_OVERRIDE_FILE" "$@"
}
psql_db() {
    compose exec -T db psql --username postgres --dbname postgres \
        --set ON_ERROR_STOP=1 "$@"
}

[ -L "$SUPABASE_FUNCTIONS_DEPLOY_DIR" ] && \
    [ -s "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.source.sha256" ] && \
    [ -s "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.project-release.sha" ] && \
    [ -s "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.project-manifest.sha256" ] && \
    [ -s "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.backend-wire" ] && \
    [ -s "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.migration-policy" ] && \
    [ -s "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.supabase-upstream.sha" ] && \
    [ -s "$SUPABASE_FUNCTIONS_DEPLOY_DIR/main/index.ts" ] && \
    [ -s "$SUPABASE_FUNCTIONS_DEPLOY_DIR/access-applications/index.ts" ] && \
    [ -s "$SUPABASE_FUNCTIONS_DEPLOY_DIR/invite-member/index.ts" ] || {
        printf '%s\n' "deployed Edge Function tree is incomplete" >&2
        exit 65
    }

hash_tree() {
    tree_root=$1
    tree_label=$2
    LC_ALL=C find "$tree_root" -type f -print | LC_ALL=C sort | while IFS= read -r source_file; do
        relative=${source_file#"$tree_root"/}
        file_hash=$(sha256sum "$source_file" | awk '{print $1}')
        printf '%s  %s/%s\n' "$file_hash" "$tree_label" "$relative"
    done
}
deployed_function_digest=$(
    {
        hash_tree "$SUPABASE_FUNCTIONS_DEPLOY_DIR/main" main
        hash_tree "$SUPABASE_FUNCTIONS_DEPLOY_DIR/access-applications" access-applications
        hash_tree "$SUPABASE_FUNCTIONS_DEPLOY_DIR/invite-member" invite-member
    } | LC_ALL=C sort | sha256sum | awk '{print $1}'
)
[ "$(tr -d '\r\n' < "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.source.sha256")" = "$deployed_function_digest" ] && \
    [ "$(tr -d '\r\n' < "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.project-release.sha")" = "$expected_release_sha" ] && \
    [ "$(tr -d '\r\n' < "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.project-manifest.sha256")" = "$backend_manifest" ] && \
    [ "$(tr -d '\r\n' < "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.backend-wire")" = "$backend_wire" ] && \
    [ "$(tr -d '\r\n' < "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.migration-policy")" = "$backend_policy" ] && \
    [ "$(tr -d '\r\n' < "$SUPABASE_FUNCTIONS_DEPLOY_DIR/.supabase-upstream.sha")" = "$SUPABASE_UPSTREAM_SHA" ] || {
    printf '%s\n' "deployed Edge Function tree is not bound to the exact backend release" >&2
    exit 65
}

source_count=0
for migration in "$migration_dir"/*.sql; do
    [ -f "$migration" ] || { printf '%s\n' "no Supabase migrations were found" >&2; exit 66; }
    source_count=$((source_count + 1))
    migration_name=$(basename -- "$migration")
    migration_digest=$(sha256sum "$migration" | awk '{print $1}')
    registered=$(psql_db --tuples-only --no-align \
        --set "migration_name=$migration_name" \
        --command "select digest || ':' || status from private.schema_migrations where name = :'migration_name';")
    [ "$registered" = "$migration_digest:applied" ] || {
        printf '%s\n' "source migration is not registered as applied: $migration_name" >&2
        exit 65
    }
done
registered_count=$(psql_db --tuples-only --no-align --command \
    "select count(*) from private.schema_migrations where status = 'applied';")
[ "$registered_count" = "$source_count" ] || {
    printf '%s\n' "database migration ledger differs from the release source" >&2
    exit 65
}

backend_record=$(psql_db --tuples-only --no-align \
    --set "release_sha=$expected_release_sha" --command \
    "select source_manifest_sha256 || ':' || wire_compatibility || ':' || migration_policy || ':' || function_digest || ':' || supabase_upstream_sha || ':' || status from private.mvp_backend_releases where release_sha = :'release_sha';")
expected_backend_record="$backend_manifest:$backend_wire:$backend_policy:$deployed_function_digest:$SUPABASE_UPSTREAM_SHA:$expected_backend_status"
[ "$backend_record" = "$expected_backend_record" ] || {
    printf '%s\n' "database backend release record differs from the exact release source" >&2
    exit 65
}
active_backend_count=$(psql_db --tuples-only --no-align --command \
    "select count(*) from private.mvp_backend_releases where status = 'active';")
if [ "$expected_backend_status" = active ]; then
    [ "$active_backend_count" = 1 ] || {
        printf '%s\n' "database must have exactly one active backend release" >&2
        exit 65
    }
    for state_file in backend.sha backend.manifest backend.wire backend.policy backend.functions backend.upstream; do
        [ -s "$MVP_RELEASE_STATE_DIR/$state_file" ] || {
            printf '%s\n' "active backend release state is incomplete: $state_file" >&2
            exit 65
        }
    done
    [ "$(tr -d '\r\n' < "$MVP_RELEASE_STATE_DIR/backend.sha")" = "$expected_release_sha" ] && \
        [ "$(tr -d '\r\n' < "$MVP_RELEASE_STATE_DIR/backend.manifest")" = "$backend_manifest" ] && \
        [ "$(tr -d '\r\n' < "$MVP_RELEASE_STATE_DIR/backend.wire")" = "$backend_wire" ] && \
        [ "$(tr -d '\r\n' < "$MVP_RELEASE_STATE_DIR/backend.policy")" = "$backend_policy" ] && \
        [ "$(tr -d '\r\n' < "$MVP_RELEASE_STATE_DIR/backend.functions")" = "$deployed_function_digest" ] && \
        [ "$(tr -d '\r\n' < "$MVP_RELEASE_STATE_DIR/backend.upstream")" = "$SUPABASE_UPSTREAM_SHA" ] || {
        printf '%s\n' "host backend release state differs from the database release record" >&2
        exit 65
    }
else
    [ "$active_backend_count" -le 1 ] || {
        printf '%s\n' "database has multiple active backend releases" >&2
        exit 65
    }
fi

for signature in \
    'public.bind_device_session(uuid,uuid)' \
    'public.bootstrap_mvp_first_owner(uuid,text,uuid,text,text,uuid,text,text,text)' \
    'public.register_device(uuid,uuid,text,text,text,text,text)' \
    'public.pull_sync_events(uuid,bigint,integer)' \
    'public.transition_workflow(uuid,uuid,bigint,text,text)' \
    'public.put_user_ai_credential(jsonb)' \
    'public.get_user_ai_credential(text)' \
    'public.list_user_ai_credentials()' \
    'public.delete_user_ai_credential(text)' \
    'public.put_mvp_first_owner_key_envelope(integer,text,text,text)' \
    'public.submit_access_application(text,text,text,integer,text,text,text)' \
    'public.list_access_applications(text,uuid,integer)' \
    'public.decide_access_application(uuid,text,text,text,text)' \
    'public.hook_v9_before_user_created(jsonb)'; do
    exists=$(psql_db --tuples-only --no-align --set "signature=$signature" --command \
        "select (to_regprocedure(:'signature') is not null)::text;")
    [ "$exists" = true ] || {
        printf '%s\n' "critical Supabase function is missing: $signature" >&2
        exit 65
    }
done

bootstrap_acl=$(psql_db --tuples-only --no-align --command \
    "select (not has_function_privilege('authenticated','public.bootstrap_mvp_first_owner(uuid,text,uuid,text,text,uuid,text,text,text)','EXECUTE') and has_function_privilege('service_role','public.bootstrap_mvp_first_owner(uuid,text,uuid,text,text,uuid,text,text,text)','EXECUTE') and not has_function_privilege('authenticated','public.bootstrap_organization(text,text,uuid,text,text,text,text)','EXECUTE') and not has_function_privilege('authenticated','public.bootstrap_organization(text,text,uuid,text,text,text,text,uuid)','EXECUTE'))::text;")
[ "$bootstrap_acl" = true ] || {
    printf '%s\n' "first-Owner bootstrap grants are not service-role-only" >&2
    exit 65
}
envelope_acl=$(psql_db --tuples-only --no-align --command \
    "select (has_function_privilege('authenticated','public.put_mvp_first_owner_key_envelope(integer,text,text,text)','EXECUTE') and not has_function_privilege('anon','public.put_mvp_first_owner_key_envelope(integer,text,text,text)','EXECUTE') and not has_function_privilege('service_role','public.put_mvp_first_owner_key_envelope(integer,text,text,text)','EXECUTE') and not has_table_privilege('authenticated','public.key_envelopes','INSERT') and not exists (select 1 from pg_proc p cross join lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a where p.oid = to_regprocedure('public.put_mvp_first_owner_key_envelope(integer,text,text,text)') and a.grantee = 0 and a.privilege_type = 'EXECUTE'))::text;")
[ "$envelope_acl" = true ] || {
    printf '%s\n' "first-Owner key-envelope RPC grants are not authenticated-only" >&2
    exit 65
}
register_device_acl=$(psql_db --tuples-only --no-align --command \
    "select (has_function_privilege('authenticated','public.register_device(uuid,uuid,text,text,text,text,text)','EXECUTE') and not has_function_privilege('anon','public.register_device(uuid,uuid,text,text,text,text,text)','EXECUTE') and not has_function_privilege('service_role','public.register_device(uuid,uuid,text,text,text,text,text)','EXECUTE') and not exists (select 1 from pg_proc p cross join lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a where p.oid = to_regprocedure('public.register_device(uuid,uuid,text,text,text,text,text)') and a.grantee = 0 and a.privilege_type = 'EXECUTE'))::text;")
[ "$register_device_acl" = true ] || {
    printf '%s\n' "device registration RPC grants are not authenticated-only" >&2
    exit 65
}

compose exec -T functions /bin/sh -eu -c '
    [ "$VERIFY_JWT" = false ]
    [ -n "$ACCESS_APPLICATION_HMAC_KEY" ]
    [ -n "$ACCESS_APPLICATION_ENCRYPTION_KEY" ]
    [ -f /home/deno/functions/access-applications/index.ts ]
    [ -f /home/deno/functions/invite-member/index.ts ]
    [ -f /home/deno/functions/main/index.ts ]
'

printf '%s\n' "[SUPABASE-APP] Exact backend release, migration ledger, critical RPCs and mounted Edge Functions verified."
