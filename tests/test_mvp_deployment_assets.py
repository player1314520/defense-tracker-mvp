"""Static release gates for the isolated MVP deployment surface."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import json
import os
import re
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
MVP = ROOT / "deploy" / "mvp"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def test_deployment_shell_scripts_are_pinned_to_lf_in_git():
    attributes = read(ROOT / ".gitattributes")
    assert re.search(r"(?m)^\*\.sh\s+text\s+eol=lf\s*$", attributes)
    for script in sorted(MVP.rglob("*.sh")):
        payload = script.read_bytes()
        assert payload.startswith(b"#!")
        assert b"\r\n" not in payload


def test_embedded_deployment_python_has_valid_syntax():
    checked = 0
    for script in sorted((MVP / "bin").glob("*.sh")):
        for index, source in enumerate(
            re.findall(r"<<'PY'\n(.*?)\nPY", read(script), flags=re.DOTALL),
            start=1,
        ):
            compile(source, f"{script.name}:heredoc-{index}", "exec")
            checked += 1
    assert checked >= 5


def test_production_compose_exposes_only_portal_and_edge_with_hardening():
    compose = yaml.safe_load(read(MVP / "docker-compose.production.yml"))
    assert set(compose["services"]) == {"portal", "edge"}
    portal = compose["services"]["portal"]
    edge = compose["services"]["edge"]

    assert "build" not in portal
    assert "PORTAL_IMAGE" in portal["image"]
    assert portal["read_only"] is True
    assert portal["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in portal["security_opt"]
    assert portal["ports"][0].startswith("127.0.0.1:")
    assert portal["environment"]["V9_MAX_ACTIVE_USERS"] == "100"
    assert portal["environment"]["V9_MAX_CONCURRENT_REQUESTS"] == "20"
    assert portal["environment"]["V9_LEGACY_COORDINATOR_ENABLED"] == "false"
    assert portal["environment"]["V9_PRODUCTION_MODE"] == "true"
    assert "ACCESS_APPLICATIONS_ENABLED" in portal["environment"][
        "V9_ACCESS_APPLICATIONS_ENABLED"
    ]
    assert portal["environment"]["V9_MAX_EVENTS_PER_USER_PER_DAY"] == "1000"
    assert "MVP_EXPECTED_RELEASE_SHA" in portal["environment"][
        "DEFENSE_TRACKER_BUILD_COMMIT"
    ]
    assert portal["secrets"] == ["supabase_publishable_key"]
    assert portal["healthcheck"]["test"]

    assert edge["network_mode"] == "host"
    assert edge["read_only"] is True
    assert edge["cap_drop"] == ["ALL"]
    assert edge["cap_add"] == ["NET_BIND_SERVICE"]
    assert "no-new-privileges:true" in edge["security_opt"]
    assert edge["healthcheck"]["test"]
    assert edge["depends_on"]["portal"]["condition"] == "service_healthy"
    assert set(compose["volumes"]) == {"portal-state", "caddy-data", "caddy-config"}
    assert set(portal["networks"]) == {"portal-internal", "portal-egress"}
    assert compose["networks"]["portal-internal"]["internal"] is True
    assert compose["networks"]["portal-egress"]["internal"] is False


def test_reverse_proxy_uses_two_exact_domains_and_loopback_upstreams():
    caddy = read(MVP / "Caddyfile")
    assert "https://{$PORTAL_DOMAIN}" in caddy
    assert "https://{$API_DOMAIN}" in caddy
    assert "{$PORTAL_UPSTREAM}" in caddy
    assert "{$SUPABASE_UPSTREAM}" in caddy
    assert "*." not in caddy
    assert "@public_api" in caddy
    assert "@realtime_api" in caddy
    assert " path \\\n" not in caddy
    for path in ("/auth/v1/*", "/rest/v1/*", "/storage/v1/*"):
        assert path in caddy
    for path in (
        "/functions/v1/access-applications",
        "/functions/v1/access-applications/*",
        "/functions/v1/invite-member",
        "/functions/v1/invite-member/*",
    ):
        assert path in caddy
    assert "/functions/v1/*" not in caddy
    assert "@portal_public" in caddy
    for path in ("/health", "/ready", "/api/status", "/portal/*"):
        assert path in caddy
    assert "max_size 256KB" in caddy
    assert "max_size 32MB" in caddy
    # Caddy's unhealthy_request_count is a passive load-balancing health
    # signal, not a global or per-source request limiter.  Do not present it as
    # an edge-control substitute for the required upstream firewall/WAF.
    assert "unhealthy_request_count" not in caddy
    assert "header_up -X-Real-IP" in caddy
    assert "header_up -X-Forwarded-For" in caddy
    assert "header_up -CF-Connecting-IP" in caddy
    assert "header_up -X-V9-Client-IP" in caddy
    assert "trusted_proxies static {$WAF_TRUSTED_PROXY_CIDRS}" in caddy
    assert "trusted_proxies_strict" in caddy
    assert "header_up X-V9-Client-IP {client_ip}" in caddy
    assert "header_up X-Forwarded-For {client_ip}" in caddy
    api_proxy = caddy.split("https://{$API_DOMAIN}", 1)[1]
    source_header_steps = (
        "header_up -X-Real-IP",
        "header_up -X-Forwarded-For",
        "header_up -CF-Connecting-IP",
        "header_up -X-V9-Client-IP",
        "header_up X-V9-Client-IP {client_ip}",
        "header_up X-Forwarded-For {client_ip}",
    )
    assert [api_proxy.index(step) for step in source_header_steps] == sorted(
        api_proxy.index(step) for step in source_header_steps
    )
    assert "respond 404" in caddy
    assert "tls_insecure_skip_verify" not in caddy

    compose = read(MVP / "docker-compose.production.yml")
    assert "127.0.0.1:${PORTAL_LOOPBACK_PORT" in compose
    assert 'SUPABASE_UPSTREAM: "127.0.0.1:' in compose
    assert "app.py" not in compose
    assert "feishu_cloud" not in compose

    override = read(MVP / "supabase.production.override.yml")
    assert "GOTRUE_HOOK_BEFORE_USER_CREATED_ENABLED" in override
    assert "pg-functions://postgres/public/hook_v9_before_user_created" in override
    assert "V9_AUTH_HOOK_ENABLED" in override
    assert "ACCESS_APPLICATION_HMAC_KEY" in override
    assert "ACCESS_APPLICATION_ENCRYPTION_KEY" in override
    assert "V9_ACCESS_APPLICATIONS_ENABLED" in override
    assert "SUPABASE_FUNCTIONS_DEPLOY_DIR" in override
    assert "FILE_SIZE_LIMIT: \"16777232\"" in override
    assert "kong:" in override
    assert "host_ip: 127.0.0.1" in override
    assert "supavisor:" in override
    assert "ports: !override []" in override


def test_portal_image_is_minimal_nonroot_and_generated_from_git_allowlist():
    dockerfile = read(MVP / "portal.Dockerfile")
    assert "ARG PYTHON_BASE_IMAGE" in dockerfile
    assert 'org.opencontainers.image.revision="${GIT_SHA}"' in dockerfile
    assert 'io.defensetracker.mvp.backend-source-manifest="${BACKEND_SOURCE_MANIFEST}"' in dockerfile
    assert 'io.defensetracker.mvp.backend-wire-compatibility="${BACKEND_WIRE_COMPATIBILITY}"' in dockerfile
    assert 'io.defensetracker.mvp.backend-migration-policy="${BACKEND_MIGRATION_POLICY}"' in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "v9_cloud.py /app/v9_cloud.py" in dockerfile
    assert "feishu_webhook_security.py /app/feishu_webhook_security.py" in dockerfile
    assert "v9 /app/v9" in dockerfile
    assert "web/v9-portal /app/web/v9-portal" in dockerfile
    for forbidden in ("app.py", "templates", "static", "素材库", "tests", ".env"):
        assert forbidden not in dockerfile

    context_builder = read(ROOT / "scripts" / "prepare_mvp_portal_context.py")
    assert '"v9_cloud.py"' in context_builder
    assert '"feishu_webhook_security.py"' in context_builder
    assert '"web/v9-portal/"' in context_builder
    assert '"deploy/requirements.cloud.txt"' in context_builder
    assert '"素材库"' in context_builder  # explicit denylist
    assert '"tests"' in context_builder  # explicit denylist
    assert '"git", "-C"' in context_builder
    assert '"show", f"HEAD:{relative}"' in context_builder
    assert "untracked-files=all" in context_builder

    entrypoint = read(MVP / "portal-entrypoint.sh")
    assert "V9_PRODUCTION_MODE must be true" in entrypoint
    assert "V9_ACCESS_APPLICATIONS_ENABLED must be true or false" in entrypoint
    assert "V9_MAX_EVENTS_PER_USER_PER_DAY must be 1000" in entrypoint
    assert "DEFENSE_TRACKER_BUILD_COMMIT must be a full lowercase Git SHA" in entrypoint


def test_retention_job_uses_only_service_role_rpc_and_aggregate_output():
    purge = read(MVP / "bin" / "purge-access-applications.sh")
    service = read(MVP / "systemd" / "defense-tracker-retention.service")
    timer = read(MVP / "systemd" / "defense-tracker-retention.timer")

    assert "SUPABASE_SECRET_KEY" in purge
    assert "/rest/v1/rpc/purge_expired_access_application_data" in purge
    assert "Authorization: Bearer $secret_key" in purge
    assert '--header "@$header_file"' in purge
    assert '--header "Authorization: Bearer $secret_key"' not in purge
    assert "unset secret_key\nstatus=$(curl" in purge
    assert "set -x" not in purge
    assert "print(matches[0], end=\"\")" in purge
    assert "[RETENTION]" in purge
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    assert "03:05:00 Asia/Shanghai" in timer


def test_backup_and_restore_are_encrypted_offsite_and_isolated():
    backup = read(MVP / "bin" / "backup.sh")
    restore = read(MVP / "bin" / "restore-dry-run.sh")

    for required in (
        "pg_dumpall --globals-only --no-role-passwords",
        "pg_dump --format=custom",
        "postgres.dump",
        "_supabase.dump",
        "postgres-roles.txt",
        "db-config.tar",
        "storage.tar",
        "supabase-config.tar",
        "mvp-config.tar",
        "payload.sha256",
    ):
        assert required in backup
    assert "age --recipients-file" in backup
    assert "rclone" in backup
    assert "--immutable" in backup
    assert "remote_hash" in backup
    assert "set -x" not in backup
    assert "rclone delete" not in backup
    assert "rclone purge" not in backup
    assert 'stop --timeout 60 kong auth rest realtime storage' in backup
    assert "[BACKUP] Write services stopped for the maintenance snapshot." in backup
    assert "resume_write_services" in backup
    assert "supabase_upstream_sha" in backup

    assert "age --decrypt" in restore
    assert "sha256sum --check --status" in restore
    assert "--network none" in restore
    assert "--pull never" in restore
    assert "docker volume create" in restore
    assert "storage-check" in restore
    assert "supabase-config-check" in restore
    assert "mvp-config-check" in restore
    assert "config_volume_name" in restore
    assert "restore.log" in restore
    assert "pg_restore --exit-on-error" in restore
    assert "postgres-globals.sql" in restore
    assert "postgres-roles.txt" in restore
    assert "postgres-globals-existing.sql" in restore
    assert "!/^CREATE ROLE /" in restore
    assert "supabase_upstream_sha" in restore
    assert "< \"$payload/postgres.sql\"" not in restore
    assert "docker compose down" not in restore
    assert "SUPABASE_STORAGE_DATA_DIR" not in restore


def test_release_and_rollback_retain_git_sha_images():
    release = read(MVP / "bin" / "release.sh")
    rollback = read(MVP / "bin" / "rollback.sh")
    assert "^[0-9a-f]{40}$" in release
    assert "REPOSITORY_AT_SHA256" in release
    assert "^sha256:[0-9a-f]{64}$" in release
    assert 'docker pull "$candidate_image"' in release
    assert 'candidate_image="$image_repository:$release_sha"' not in release
    assert "org.opencontainers.image.revision" in release
    assert "previous.image" in release
    assert "--wait" in release
    assert "docker image prune" not in release
    assert "restore_current" in release
    assert 'install-supabase-app.sh" "$release_sha" "$config_file"' in release
    assert 'verify-supabase-app.sh" "$release_sha" "$config_file"' in release
    assert "probe-public.py" in release
    assert 'https://$PORTAL_DOMAIN/ready' not in release  # one redaction-safe probe owns live checks

    # Every source/image/Compose gate must fail before the first Supabase
    # mutation.  The old Portal is allowed to stay up only when it declares
    # compatibility with the backend wire contract being installed.
    install_at = release.index('install-supabase-app.sh" "$release_sha" "$config_file"')
    for pre_mutation_gate in (
        "project checkout must be clean",
        "project checkout HEAD does not match requested release SHA",
        'docker pull "$candidate_image"',
        "candidate image backend source manifest",
        "candidate image backend wire compatibility",
        "candidate image backend migration policy",
        "config --quiet",
        "current Portal is not compatible with the candidate backend wire contract",
    ):
        assert release.index(pre_mutation_gate) < install_at
    assert "backend migrations are forward-only" in release

    assert "previous.image" in rollback
    assert "org.opencontainers.image.revision" in rollback
    assert "io.defensetracker.mvp.backend-wire-compatibility" in rollback
    assert "retained Portal image must be pinned by repository digest" in rollback
    assert "rollback Portal is incompatible with the active backend wire contract" in rollback
    assert rollback.index("rollback Portal is incompatible") < rollback.index(
        'docker compose --env-file "$config_file" --file "$compose_file" up'
    )
    assert 'verify-supabase-app.sh" "$backend_sha" "$config_file"' in rollback
    assert "--wait" in rollback
    assert "docker image prune" not in rollback


def test_supabase_install_is_hash_tracked_and_deploys_migrations_and_functions():
    installer = read(MVP / "bin" / "install-supabase-app.sh")
    verifier = read(MVP / "bin" / "verify-supabase-app.sh")
    starter = read(MVP / "bin" / "start-supabase.sh")
    preflight = read(MVP / "bin" / "preflight.sh")

    assert "supabase/migrations" in installer
    assert "*.sql" in installer
    assert "schema_migrations" in installer
    assert "sha256sum" in installer
    assert "migration digest changed after registration" in installer
    assert "access-applications" in installer
    assert "invite-member" in installer
    assert "volumes/functions/main" in installer
    assert "SUPABASE_FUNCTIONS_DEPLOY_DIR" in installer
    assert "project checkout must be clean" in installer
    assert "project checkout HEAD does not match expected release SHA" in installer
    assert "backend-release-metadata.py" in installer
    assert "mvp_backend_releases" in installer
    assert "source_manifest_sha256" in installer
    assert "wire_compatibility" in installer
    assert "supabase_upstream_sha" in installer
    assert installer.index("project checkout must be clean") < installer.index(".supabase-app.lock")
    assert installer.index(".supabase-app.lock") < installer.index("hash_tree()")
    assert installer.index("project checkout must be clean") < installer.index("mv -Tf")
    assert installer.index("project checkout must be clean") < installer.index("psql_db --quiet")
    assert "--no-deps --force-recreate" in installer
    assert "--prepare-functions" in installer
    assert 'release_dir="$deploy_root/releases/$expected_release_sha-$function_digest"' in installer
    assert 'ln -s "releases/$expected_release_sha-$function_digest"' in installer
    assert 'install-supabase-app.sh" --prepare-functions "$release_sha" "$config_file"' in starter
    assert 'install-supabase-app.sh" "$release_sha" "$config_file"' in starter
    assert 'preflight.sh" "$config_file"' in starter

    for signature in (
        "public.bind_device_session(uuid,uuid)",
        "public.bootstrap_mvp_first_owner(uuid,text,uuid,text,text,uuid,text,text,text)",
        "public.put_user_ai_credential(jsonb)",
        "public.put_mvp_first_owner_key_envelope(integer,text,text,text)",
        "public.submit_access_application(text,text,text,integer,text,text,text)",
        "public.purge_expired_access_application_data()",
        "public.hook_v9_before_user_created(jsonb)",
    ):
        assert signature in verifier
    assert "source migration is not registered as applied" in verifier
    assert "has_function_privilege('authenticated'" in verifier
    assert "has_function_privilege('service_role'" in verifier
    assert "bootstrap_organization" in verifier
    assert "first-Owner key-envelope RPC grants are not authenticated-only" in verifier
    assert "not has_table_privilege('authenticated','public.key_envelopes','INSERT')" in verifier
    assert "aclexplode" in verifier
    assert "a.grantee = 0" in verifier
    assert "device registration RPC grants are not authenticated-only" in verifier
    assert "database capacity or daily-event quota contract is missing" in verifier
    assert "access retention RPC grants are not service-role-only" in verifier
    assert "register_device_acl" in verifier
    assert "mvp_backend_releases" in verifier
    assert "backend.sha" in verifier
    assert "backend.manifest" in verifier
    assert "backend.wire" in verifier
    migration_025 = read(
        ROOT / "supabase" / "migrations" / "202608100025_mvp_first_owner_key_envelope.sql"
    )
    assert "create or replace function public.put_mvp_first_owner_key_envelope" in migration_025
    migration_026 = read(
        ROOT / "supabase" / "migrations" / "202608100026_mvp_idempotent_device_registration.sql"
    )
    assert "create or replace function public.register_device" in migration_026
    assert "202608100026_mvp_idempotent_device_registration.sql" in installer
    assert "SUPABASE_PUBLISHABLE_KEY" in preflight
    assert "OFFICIAL_SUPABASE_ENV_FILE" in preflight
    assert "official_key" in preflight
    assert "SUPABASE_SERVICE_ROLE_KEY" in preflight
    assert "compare_digest" in preflight
    assert "FUNCTIONS_VERIFY_JWT" in preflight
    assert "domain_pattern.fullmatch" in preflight
    assert "1:1:1:1:finalized" in preflight
    assert '"$auth_users" -le 100' in preflight

    image_builder = read(MVP / "bin" / "build-portal-image.sh")
    assert "RepoDigests" in image_builder
    assert "Immutable release reference" in image_builder


def test_backend_release_manifest_is_git_exact_and_rejects_invalid_policy(tmp_path):
    helper = MVP / "bin" / "backend-release-metadata.py"
    compatibility_contract = json.loads(read(MVP / "backend-compatibility.json"))
    assert compatibility_contract["wire_compatibility"] == "mvp-wire-v1"
    assert compatibility_contract["migration_policy"] == "expand-contract"
    repo = tmp_path / "repo"
    required = {
        "supabase/migrations/202608100025_mvp_first_owner_key_envelope.sql": "select 25;\n",
        "supabase/migrations/202608100026_mvp_idempotent_device_registration.sql": "select 26;\n",
        "supabase/functions/access-applications/index.ts": "export {};\n",
        "supabase/functions/invite-member/index.ts": "export {};\n",
        "deploy/mvp/backend-compatibility.json": json.dumps(
            {
                "schema": 1,
                "wire_compatibility": "mvp-wire-v1",
                "migration_policy": "expand-contract",
            }
        ),
    }
    for relative, content in required.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    env = {
        "GIT_AUTHOR_NAME": "MVP Test",
        "GIT_AUTHOR_EMAIL": "mvp-test@example.invalid",
        "GIT_COMMITTER_NAME": "MVP Test",
        "GIT_COMMITTER_EMAIL": "mvp-test@example.invalid",
    }
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "valid"],
        check=True,
        env={**os.environ, **env},
    )
    first_sha = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()
    first = subprocess.run(
        [sys.executable, str(helper), "--repo", str(repo), "--git-sha", first_sha],
        check=True,
        capture_output=True,
        text=True,
    )
    first_metadata = json.loads(first.stdout)
    assert first_metadata["release_sha"] == first_sha
    assert first_metadata["wire_compatibility"] == "mvp-wire-v1"
    assert first_metadata["migration_policy"] == "expand-contract"
    assert re.fullmatch(r"[0-9a-f]{64}", first_metadata["source_manifest_sha256"])

    registration = repo / "supabase/migrations/202608100026_mvp_idempotent_device_registration.sql"
    registration.write_text("select 27;\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", str(registration)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "changed migration"],
        check=True,
        env={**os.environ, **env},
    )
    second_sha = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()
    second = subprocess.run(
        [sys.executable, str(helper), "--repo", str(repo), "--git-sha", second_sha],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(second.stdout)["source_manifest_sha256"] != first_metadata[
        "source_manifest_sha256"
    ]

    compatibility = repo / "deploy/mvp/backend-compatibility.json"
    compatibility.write_text(
        json.dumps(
            {
                "schema": 1,
                "wire_compatibility": "mvp-wire-v1",
                "migration_policy": "destructive",
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", str(compatibility)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", "invalid policy"],
        check=True,
        env={**os.environ, **env},
    )
    invalid_sha = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()
    invalid = subprocess.run(
        [sys.executable, str(helper), "--repo", str(repo), "--git-sha", invalid_sha],
        capture_output=True,
        text=True,
    )
    assert invalid.returncode != 0
    assert "expand-contract" in invalid.stderr


def test_public_probe_covers_runtime_without_printing_credentials():
    probe = read(MVP / "bin" / "probe-public.py")
    for endpoint in (
        "/ready",
        "/portal/config.json",
        "/api/status",
        "/auth/v1/health",
        "/storage/v1/status",
        "/functions/v1/access-applications",
        "/realtime/v1/websocket",
    ):
        assert endpoint in probe
    assert "Sec-WebSocket-Key" in probe
    assert "101" in probe
    assert "hmac.compare_digest" in probe
    assert "verify_release_metadata" in probe
    assert "load_product_version_metadata" in probe
    assert 'source_root / "version.json"' in probe
    assert 'Path("/app/version.json")' in probe
    assert '"wire_compatibility": "mvp-wire-v1"' in probe
    assert "authentication-required business flows are not part of this probe" in probe
    assert "print(key" not in probe


def test_external_origin_probe_is_redaction_safe_and_fail_closed():
    probe = read(MVP / "bin" / "probe-origin-isolation.py")
    for protected_name in (
        "DEFENSE_TRACKER_STAGING_ORIGIN_TARGET",
        "DEFENSE_TRACKER_PRODUCTION_ORIGIN_TARGET",
        "DEFENSE_TRACKER_ORIGIN_EVIDENCE_HMAC_KEY",
    ):
        assert protected_name in probe
    for gate in (
        "public_edge_https_reachable",
        "origin_tcp_80_blocked",
        "origin_tcp_443_blocked",
        "origin_sni_443_blocked",
    ):
        assert gate in probe
    assert "hmac.new" in probe
    assert "target_hmac_sha256" in probe
    assert "address.is_global" in probe
    assert "public_addresses & target_addresses" in probe
    assert '"/health"' in probe
    assert "print(target" not in probe
    assert "json.dumps(evidence" in probe
    assert '"status": "pass" if passed else "fail"' in probe


def test_public_probe_reads_release_values_from_version_json(tmp_path):
    script = MVP / "bin" / "probe-public.py"
    spec = importlib.util.spec_from_file_location("defense_probe_public", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    version_path = tmp_path / "version.json"
    version_path.write_text(
        json.dumps(
            {
                "schema": 1,
                "semantic_version": "10.2.3",
                "display_version": "V10",
                "release_tag": "v10.2.3",
            }
        ),
        encoding="utf-8",
    )

    version = module.load_product_version_metadata(version_path)
    payload = {
        "version": "10.2.3",
        "display_version": "V10",
        "release_tag": "v10.2.3",
        "build_commit": "a" * 40,
        "wire_compatibility": "mvp-wire-v1",
    }

    module.verify_release_metadata(payload, "a" * 40, version)
    with pytest.raises(module.ProbeFailure):
        module.verify_release_metadata(payload | {"version": "9.0.0"}, "a" * 40, version)


def test_first_owner_bootstrap_is_out_of_band_empty_database_and_idempotent():
    bootstrap = read(MVP / "bin" / "bootstrap-owner.sh")
    assert "OWNER_EMAIL_FILE" in bootstrap
    assert "OWNER_BOOTSTRAP_MANIFEST" in bootstrap
    assert "mvp_owner_bootstrap" in bootstrap
    assert "only an empty database can begin Owner bootstrap" in bootstrap
    assert "V9_AUTH_HOOK_ENABLED" in bootstrap
    assert "DISABLE_SIGNUP" in bootstrap
    assert "/auth/v1/invite" in bootstrap
    assert "/rest/v1/rpc/bootstrap_mvp_first_owner" in bootstrap
    assert '"schema_version"' in bootstrap
    assert '"key_algorithm"' in bootstrap
    assert '"device_kind"' in bootstrap
    assert '"p_owner_user_id"' in bootstrap
    assert "SERVICE_ROLE_KEY" in bootstrap
    assert "idempotent" in bootstrap
    assert "--finalize" in bootstrap
    assert "bootstrap_organization" not in bootstrap
    assert "owner email" not in bootstrap.lower()
    assert "cat \"$owner_email_file\"" not in bootstrap
    assert "cat \"$owner_manifest_file\"" not in bootstrap


def test_supabase_required_env_has_current_auth_url_and_function_secrets():
    required = read(MVP / "supabase.required.env.example")
    assert "API_EXTERNAL_URL=https://api.example.invalid/auth/v1" in required
    assert "FUNCTIONS_VERIFY_JWT=false" in required
    assert 'SUPABASE_PUBLISHABLE_KEYS={"default":"REPLACE_WITH_GENERATED_OPAQUE_PUBLISHABLE_KEY"}' in required
    assert "ACCESS_APPLICATION_HMAC_KEY=" in required
    assert "ACCESS_APPLICATION_ENCRYPTION_KEY=" in required
    assert "ACCESS_APPLICATION_ENCRYPTION_KEY_VERSION=1" in required
    for port in range(49231, 49236):
        assert (
            f"http://127.0.0.1:{port}/api/v9/auth/callback" in required
        )
    assert "DISABLE_SIGNUP=true" in required
    production = read(MVP / "production.env.example")
    assert "SUPABASE_FUNCTIONS_DEPLOY_DIR=" in production
    assert "PORTAL_IMAGE=registry.example.invalid/defense-tracker/portal@sha256:" in production
    assert "V9_AUTH_HOOK_ENABLED=false" in production
    assert "ACCESS_APPLICATIONS_ENABLED=false" in production
    assert "MVP_EXTERNAL_WAF_ENABLED=true" in production
    assert "MVP_WAF_REALTIME_WEBSOCKET_ALLOWED=true" in production
    assert "WAF_TRUSTED_PROXY_CIDRS=" in production
    preflight = read(MVP / "bin" / "preflight.sh")
    assert "defense-tracker-backup.timer" in preflight
    assert "defense-tracker-retention.timer" in preflight
    assert "systemctl is-enabled --quiet" in preflight
    assert "systemctl is-active --quiet" in preflight
    assert "WAF flags and CIDRs are configuration only" in preflight
    assert "external v9 deployment evidence origin-isolation gates" in preflight


def test_desktop_release_gate_requires_inno_sha256_timestamp_and_dual_verification():
    gate = read(ROOT / "scripts" / "Build-AndShip.ps1")
    installer = read(MVP / "DefenseTracker.iss")
    assert "RequireSignedInstaller" in gate
    assert "Assert-CleanReleaseCommit" in gate
    assert "signtool.exe" in gate
    assert "ISCC.exe" in gate
    assert '"/fd", "SHA256", "/tr", $Timestamp, "/td", "SHA256"' in gate
    assert "AzureArtifactSigning" in gate
    assert "DigiCertKeyLocker" in gate
    assert "X509NameType]::SimpleName" in gate
    assert "SigningCertificateThumbprint" not in gate
    assert "Get-AuthenticodeSignature" in gate
    assert "TimeStamperCertificate" in gate
    assert "pip install" not in gate
    assert 'Join-Path $distRoot "archive"' in gate
    assert "previous-active-release.json" in gate
    assert "recursesubdirs" in installer
    assert "PrivilegesRequired=lowest" in installer


def test_runbook_records_unverified_boundaries_and_recovery_targets():
    runbook = read(ROOT / "docs" / "MVP_DEPLOY.md")
    for required in (
        "本机没有 Docker",
        "RTO 不超过 4 小时",
        "不超过 24 小时",
        "100 个活跃账号",
        "20 个并发请求",
        "诚实边界",
        "INVITED_SIGNUP_ENABLED",
    ):
        assert required in runbook
    assert runbook.count("不能") + runbook.count("未验证") + runbook.count("不提供") >= 3
    for required in (
        "API_EXTERNAL_URL=https://<API域名>/auth/v1",
        "bootstrap-owner.sh",
        "owner-bootstrap.json",
        "--finalize",
        "停写维护窗口",
        "16 MiB + 16 byte",
        "32 MiB",
        "Realtime WebSocket",
        "Storage health",
        "202608100026_mvp_idempotent_device_registration.sql",
        "register_device(uuid,uuid,text,text,text,text,text)",
        "mvp-wire-v1",
        "需要真实用户凭据",
        "不是请求限流器",
        "上线前必须由 VPS 防火墙或 CDN/WAF",
        "provenance attestation",
        "--require-hashes",
        "不是单一 generation 的事务提交",
    ):
        assert required in runbook
