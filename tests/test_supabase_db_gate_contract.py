from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SUPABASE_CONFIG = ROOT / "supabase" / "config.toml"
SUPABASE_TESTS = ROOT / "supabase" / "tests"
SETUP_CLI_SHA = "46f7f98c7f948ad727d22c1e67fab04c223a0520"


def test_mvp_deployment_check_runs_pinned_local_database_gate():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["deployment-assets"]
    assert job["name"] == "MVP deployment assets"
    steps = job["steps"]
    setup = next(
        step
        for step in steps
        if step.get("uses", "").startswith("supabase/setup-cli@")
    )
    assert setup["uses"] == f"supabase/setup-cli@{SETUP_CLI_SHA}"
    assert str(setup["with"]["version"]) == "2.116.0"
    run_steps = "\n".join(str(step.get("run", "")) for step in steps)
    assert run_steps.index("supabase db start") < run_steps.index("supabase test db")
    assert "supabase migration list --local" in run_steps
    assert "supabase stop --no-backup" in run_steps


def test_supabase_local_config_is_explicit_and_secret_free():
    config = SUPABASE_CONFIG.read_text(encoding="utf-8")
    assert 'project_id = "defense-tracker-v9-ci"' in config
    assert "major_version = 15" in config
    assert "[db.seed]" in config and "enabled = false" in config
    lowered = config.lower()
    for forbidden in ("service_role", "access_token", "password", "secret_key"):
        assert forbidden not in lowered


def test_database_suites_are_transactional_pgtap_not_static_migration_checks():
    suites = sorted(SUPABASE_TESTS.glob("*.sql"))
    assert {path.name for path in suites} == {
        "v9_capacity_quota_test.sql",
        "v9_cross_role_rls_test.sql",
        "v9_retention_provisioning_test.sql",
    }
    combined = "\n".join(path.read_text(encoding="utf-8") for path in suites)
    for path in suites:
        sql = path.read_text(encoding="utf-8").strip().lower()
        assert sql.startswith("begin;")
        assert sql.endswith("rollback;")
        assert "select plan(" in sql
        assert "select * from finish();" in sql
        assert "commit;" not in sql
    for runtime_boundary in (
        "private.organization_seat_usage",
        "daily sync event limit exceeded",
        "on conflict (event_id) do nothing",
        "private.purge_access_application_data",
        "private.claim_member_invitation_provisioning",
        "set local role authenticated",
    ):
        assert runtime_boundary in combined
