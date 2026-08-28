#!/bin/sh
set -eu

fail() {
    printf '%s\n' "[PORTAL] $1" >&2
    exit 64
}

read_single_line_secret() {
    secret_file=$1
    [ -f "$secret_file" ] || fail "required secret file is missing"
    [ -r "$secret_file" ] || fail "required secret file is unreadable"
    value=$(tr -d '\r\n' < "$secret_file")
    [ -n "$value" ] || fail "required secret file is empty"
    printf '%s' "$value"
}

case "${V9_SUPABASE_URL:-}" in
    https://*) ;;
    *) fail "V9_SUPABASE_URL must be an exact https URL" ;;
esac

case "${V9_ALLOWED_ORIGINS:-}" in
    https://*,*) fail "MVP accepts one exact portal origin, not a list" ;;
    https://*) ;;
    *) fail "V9_ALLOWED_ORIGINS must be one exact https origin" ;;
esac

case "${V9_MAX_ACTIVE_USERS:-}" in
    100) ;;
    *) fail "V9_MAX_ACTIVE_USERS must be 100 for the MVP" ;;
esac

case "${V9_MAX_CONCURRENT_REQUESTS:-}" in
    20) ;;
    *) fail "V9_MAX_CONCURRENT_REQUESTS must be 20 for the MVP" ;;
esac

case "${V9_MAX_EVENTS_PER_USER_PER_DAY:-}" in
    1000) ;;
    *) fail "V9_MAX_EVENTS_PER_USER_PER_DAY must be 1000 for the MVP" ;;
esac

printf '%s' "${DEFENSE_TRACKER_BUILD_COMMIT:-}" | grep -Eq '^[0-9a-f]{40}$' ||
    fail "DEFENSE_TRACKER_BUILD_COMMIT must be a full lowercase Git SHA"

case "${V9_PRODUCTION_MODE:-}" in
    true) ;;
    *) fail "V9_PRODUCTION_MODE must be true" ;;
esac

case "${V9_ACCESS_APPLICATIONS_ENABLED:-}" in
    true|false) ;;
    *) fail "V9_ACCESS_APPLICATIONS_ENABLED must be true or false" ;;
esac

key_file=${V9_SUPABASE_PUBLISHABLE_KEY_FILE:-/run/secrets/supabase_publishable_key}
V9_SUPABASE_PUBLISHABLE_KEY=$(read_single_line_secret "$key_file")
export V9_SUPABASE_PUBLISHABLE_KEY

case "$V9_SUPABASE_PUBLISHABLE_KEY" in
    sb_publishable_*) ;;
    *) fail "Supabase publishable key has an unexpected format" ;;
esac

[ -d /data ] && [ -w /data ] || fail "/data must be a writable dedicated volume"
umask 077

exec gunicorn \
    --workers 1 \
    --threads "$V9_MAX_CONCURRENT_REQUESTS" \
    --worker-class gthread \
    --bind "0.0.0.0:${PORT:-8080}" \
    --timeout 30 \
    --graceful-timeout 20 \
    --keep-alive 5 \
    --access-logfile - \
    --error-logfile - \
    v9_cloud:app
