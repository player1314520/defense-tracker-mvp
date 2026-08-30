#!/bin/sh

# This file is sourced by deployment entrypoints.  File descriptor 9 is
# inherited by nested entrypoints so one release transaction can call the
# Supabase installer without dropping the global deployment lock.
acquire_mvp_deployment_lock() {
    deployment_state_dir=$1
    case "$deployment_state_dir" in
        /*) ;;
        *) printf '%s\n' "deployment state path must be absolute" >&2; return 64 ;;
    esac
    [ -d "$deployment_state_dir" ] || {
        printf '%s\n' "deployment state directory is missing" >&2
        return 66
    }
    command -v flock >/dev/null 2>&1 || {
        printf '%s\n' "required deployment lock command is missing: flock" >&2
        return 69
    }
    command -v readlink >/dev/null 2>&1 || {
        printf '%s\n' "required deployment lock command is missing: readlink" >&2
        return 69
    }

    deployment_state_real=$(CDPATH= cd -- "$deployment_state_dir" && pwd -P)
    case "$deployment_state_real" in
        /|/bin|/boot|/dev|/etc|/home|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
            printf '%s\n' "deployment state path is too broad" >&2
            return 64
            ;;
    esac
    deployment_lock_file="$deployment_state_real/.release.lock"
    case "${MVP_DEPLOYMENT_LOCK_FD:-}" in
        '')
            exec 9>"$deployment_lock_file"
            flock -n 9 || {
                printf '%s\n' "another deployment, rollback, backup or recovery is active" >&2
                return 75
            }
            MVP_DEPLOYMENT_LOCK_FD=9
            export MVP_DEPLOYMENT_LOCK_FD
            ;;
        9)
            inherited_lock=$(readlink -f /proc/self/fd/9 2>/dev/null || true)
            [ "$inherited_lock" = "$deployment_lock_file" ] || {
                printf '%s\n' "inherited deployment lock does not match the requested state directory" >&2
                return 65
            }
            flock -n 9 || {
                printf '%s\n' "inherited deployment lock is not held" >&2
                return 75
            }
            ;;
        *)
            printf '%s\n' "MVP_DEPLOYMENT_LOCK_FD must be empty or 9" >&2
            return 64
            ;;
    esac
}
