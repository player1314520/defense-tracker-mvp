#!/bin/sh
set -eu

usage() {
    printf '%s\n' "usage: $0 IMAGE_REPOSITORY BASE_IMAGE_WITH_SHA256_DIGEST [--push]" >&2
    exit 64
}

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage
image_repository=$1
base_image=$2
push_mode=${3:-}
[ -z "$push_mode" ] || [ "$push_mode" = "--push" ] || usage

printf '%s' "$image_repository" | grep -Eq '^[A-Za-z0-9._/-]+$' || {
    printf '%s\n' "IMAGE_REPOSITORY must not contain a tag or unsafe characters" >&2
    exit 64
}
printf '%s' "$base_image" | grep -Eq '^[A-Za-z0-9._/-]+(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$' || {
    printf '%s\n' "base image must be pinned by a full sha256 digest" >&2
    exit 64
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
commit=$(git -C "$project_root" rev-parse HEAD)
case "$commit" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) printf '%s\n' "unable to resolve full Git SHA" >&2; exit 65 ;;
esac
[ -z "$(git -C "$project_root" status --porcelain --untracked-files=all)" ] || {
    printf '%s\n' "project checkout must be clean before an image is built" >&2
    exit 65
}

metadata="$script_dir/backend-release-metadata.py"
backend_manifest=$(python3 "$metadata" --repo "$project_root" --git-sha "$commit" \
    --field source_manifest_sha256)
backend_wire=$(python3 "$metadata" --repo "$project_root" --git-sha "$commit" \
    --field wire_compatibility)
backend_policy=$(python3 "$metadata" --repo "$project_root" --git-sha "$commit" \
    --field migration_policy)

python3 "$project_root/scripts/prepare_mvp_portal_context.py"
context="$project_root/build/mvp-portal-context"
image="$image_repository:$commit"

docker build \
    --pull \
    --file "$context/deploy/mvp/portal.Dockerfile" \
    --build-arg "PYTHON_BASE_IMAGE=$base_image" \
    --build-arg "GIT_SHA=$commit" \
    --build-arg "BACKEND_SOURCE_MANIFEST=$backend_manifest" \
    --build-arg "BACKEND_WIRE_COMPATIBILITY=$backend_wire" \
    --build-arg "BACKEND_MIGRATION_POLICY=$backend_policy" \
    --tag "$image" \
    "$context"

revision=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image")
[ "$revision" = "$commit" ] || {
    printf '%s\n' "built image revision label does not match HEAD" >&2
    exit 65
}
built_manifest=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-source-manifest" }}' "$image")
built_wire=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-wire-compatibility" }}' "$image")
built_policy=$(docker image inspect --format '{{ index .Config.Labels "io.defensetracker.mvp.backend-migration-policy" }}' "$image")
[ "$built_manifest" = "$backend_manifest" ] && \
    [ "$built_wire" = "$backend_wire" ] && \
    [ "$built_policy" = "$backend_policy" ] || {
    printf '%s\n' "built image backend compatibility labels do not match the exact Git release" >&2
    exit 65
}

printf '%s\n' "[IMAGE] Built immutable candidate: $image"
if [ "$push_mode" = "--push" ]; then
    docker push "$image"
    printf '%s\n' "[IMAGE] Pushed after explicit --push: $image"
    pushed_reference=''
    for repository_digest in $(docker image inspect --format '{{ range .RepoDigests }}{{ println . }}{{ end }}' "$image"); do
        case "$repository_digest" in
            "$image_repository"@sha256:[0-9a-f]*)
                pushed_reference=$repository_digest
                break
                ;;
        esac
    done
    [ -n "$pushed_reference" ] && \
        printf '%s' "${pushed_reference#"$image_repository"@}" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
        printf '%s\n' "registry push did not yield an immutable repository digest" >&2
        exit 65
    }
    printf '%s\n' "[IMAGE] Immutable release reference: $pushed_reference"
else
    printf '%s\n' "[IMAGE] Not pushed. External registry writes require explicit approval and --push."
fi
