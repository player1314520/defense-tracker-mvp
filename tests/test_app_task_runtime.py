import threading

import app as tracker


def _post_client(monkeypatch):
    monkeypatch.setitem(tracker.app.config, "TESTING", False)
    client = tracker.app.test_client()
    client.set_cookie(tracker.CSRF_COOKIE, "csrf-task")
    return client, {tracker.CSRF_HEADER: "csrf-task"}


def test_capture_idempotent_replay_is_not_submitted_again(monkeypatch):
    client, headers = _post_client(monkeypatch)
    headers["Idempotency-Key"] = "capture-request-1"
    observed = {}
    monkeypatch.setattr(
        tracker.consulting_agent,
        "get_session",
        lambda session_id: {"session_id": session_id, "target_source_count": 2},
    )

    def create_job(session_id, **kwargs):
        observed["key"] = kwargs.get("idempotency_key")
        return {"job_id": "cj-existing", "idempotent_replay": True}

    monkeypatch.setattr(tracker.consulting_agent, "create_capture_job", create_job)
    monkeypatch.setattr(
        tracker.consulting_agent,
        "get_capture_job",
        lambda session_id, job_id: {
            "job_id": job_id,
            "status": "running",
            "attempts": [],
            "idempotent_replay": True,
        },
    )
    monkeypatch.setattr(tracker, "_consult_enrich_capture_job", lambda sid, job: job)
    monkeypatch.setattr(
        tracker.CAPTURE_SUBMISSION_GUARD,
        "submit",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("idempotent replay must not be submitted")
        ),
    )

    response = client.post(
        "/api/consult/sessions/cs-1/capture_to_target",
        headers=headers,
        json={"target_count": 2},
    )

    assert response.status_code == 200
    assert observed["key"] == "capture-request-1"


def test_capture_queue_full_marks_job_failed_and_returns_retry_after(monkeypatch):
    client, headers = _post_client(monkeypatch)
    updates = []
    monkeypatch.setattr(
        tracker.consulting_agent,
        "get_session",
        lambda session_id: {"session_id": session_id, "target_source_count": 2},
    )
    monkeypatch.setattr(
        tracker.consulting_agent,
        "create_capture_job",
        lambda *args, **kwargs: {"job_id": "cj-new", "idempotent_replay": False},
    )
    monkeypatch.setattr(
        tracker.consulting_agent,
        "update_capture_job",
        lambda job_id, **kwargs: updates.append((job_id, kwargs)),
    )
    monkeypatch.setattr(
        tracker.CAPTURE_SUBMISSION_GUARD,
        "submit",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            tracker.consulting_agent.TaskQueueFullError(7)
        ),
    )

    response = client.post(
        "/api/consult/sessions/cs-1/capture_to_target",
        headers=headers,
        json={"target_count": 2},
    )

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "7"
    assert response.get_json()["code"] == "QUEUE_FULL"
    assert updates == [
        (
            "cj-new",
            {
                "status": "failed",
                "stop_reason": "后台任务队列已满，请稍后重试",
                "error_code": "QUEUE_FULL",
                "retryable": True,
            },
        )
    ]


def test_draft_idempotency_key_is_forwarded_without_resubmission(monkeypatch):
    client, headers = _post_client(monkeypatch)
    headers["Idempotency-Key"] = "draft-request-1"
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "session-test-key")
    observed = {}
    monkeypatch.setattr(tracker.report_agent, "get_project", lambda project_id: {"project_id": project_id})

    def create_job(project_id, request=None, idempotency_key=None):
        observed["key"] = idempotency_key
        return {
            "job_id": "dj-existing",
            "project_id": project_id,
            "status": "done",
            "draft_id": "",
            "request": request or {},
            "idempotent_replay": True,
        }

    monkeypatch.setattr(tracker.report_agent, "create_draft_job", create_job)
    monkeypatch.setattr(
        tracker.report_agent,
        "get_draft_job",
        lambda project_id, job_id: {
            "job_id": job_id,
            "project_id": project_id,
            "status": "done",
            "draft_id": "",
            "request": {},
            "idempotent_replay": False,
        },
    )
    monkeypatch.setattr(tracker, "_agent_selected_evidence", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        tracker.REPORT_SUBMISSION_GUARD,
        "submit",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("idempotent replay must not be submitted")
        ),
    )

    response = client.post(
        "/api/agent/projects/rp-1/draft",
        headers=headers,
        json={"instruction": "draft"},
    )

    assert response.status_code == 200
    assert observed["key"] == "draft-request-1"


def test_capture_retry_submits_existing_job(monkeypatch):
    client, headers = _post_client(monkeypatch)
    submissions = []
    monkeypatch.setattr(
        tracker.consulting_agent,
        "retry_capture_job",
        lambda session_id, job_id: {
            "job_id": job_id,
            "session_id": session_id,
            "status": "queued",
            "attempts": [{"query_text": "prior attempt"}],
        },
    )
    monkeypatch.setattr(
        tracker.CAPTURE_SUBMISSION_GUARD,
        "submit",
        lambda executor, fn, *args: submissions.append((fn, args)),
    )
    monkeypatch.setattr(tracker, "_consult_enrich_capture_job", lambda sid, job: job)

    response = client.post(
        "/api/consult/sessions/cs-1/capture_jobs/cj-1/retry",
        headers=headers,
    )

    assert response.status_code == 202
    assert response.get_json()["job"]["status"] == "queued"
    assert submissions == [(tracker._run_consult_capture_job, ("cs-1", "cj-1"))]


def test_capture_retry_nonretryable_returns_stable_conflict(monkeypatch):
    client, headers = _post_client(monkeypatch)
    monkeypatch.setattr(
        tracker.consulting_agent,
        "retry_capture_job",
        lambda *args: (_ for _ in ()).throw(
            tracker.consulting_agent.TaskNotRetryableError("cj-1", "done")
        ),
    )

    response = client.post(
        "/api/consult/sessions/cs-1/capture_jobs/cj-1/retry",
        headers=headers,
    )

    assert response.status_code == 409
    assert response.get_json()["code"] == "TASK_NOT_RETRYABLE"
    assert response.get_json()["retryable"] is False


def test_draft_retry_queue_full_marks_existing_job_failed(monkeypatch):
    client, headers = _post_client(monkeypatch)
    monkeypatch.setitem(tracker.AI_CONFIG, "api_key", "session-test-key")
    updates = []
    monkeypatch.setattr(
        tracker.report_agent,
        "retry_draft_job",
        lambda project_id, job_id: {
            "job_id": job_id,
            "project_id": project_id,
            "status": "queued",
            "draft_id": "draft-preserved",
            "request": {},
        },
    )
    monkeypatch.setattr(
        tracker.report_agent,
        "update_draft_job",
        lambda job_id, **kwargs: updates.append((job_id, kwargs)),
    )
    monkeypatch.setattr(
        tracker.REPORT_SUBMISSION_GUARD,
        "submit",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            tracker.report_agent.TaskQueueFullError(9)
        ),
    )

    response = client.post(
        "/api/agent/projects/rp-1/draft_jobs/dj-1/retry",
        headers=headers,
    )

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "9"
    assert response.get_json()["code"] == "QUEUE_FULL"
    assert updates == [
        (
            "dj-1",
            {
                "status": "failed",
                "error": "后台任务队列已满，请稍后重试",
                "error_code": "QUEUE_FULL",
                "retryable": True,
            },
        )
    ]


def test_capture_cancel_route_returns_accepted_for_running_job(monkeypatch):
    client, headers = _post_client(monkeypatch)
    observed = {}

    def request_cancel(session_id, job_id, reason):
        observed.update(session_id=session_id, job_id=job_id, reason=reason)
        return {
            "job_id": job_id,
            "session_id": session_id,
            "status": "cancel_requested",
            "attempts": [],
        }

    monkeypatch.setattr(
        tracker.consulting_agent, "request_capture_job_cancel", request_cancel
    )
    monkeypatch.setattr(tracker, "_consult_enrich_capture_job", lambda sid, job: job)

    response = client.post(
        "/api/consult/sessions/cs-1/capture_jobs/cj-1/cancel",
        headers=headers,
        json={"reason": "operator stopped the run"},
    )

    assert response.status_code == 202
    assert response.get_json()["job"]["status"] == "cancel_requested"
    assert observed == {
        "session_id": "cs-1",
        "job_id": "cj-1",
        "reason": "operator stopped the run",
    }


def test_draft_block_route_returns_terminal_for_queued_job(monkeypatch):
    client, headers = _post_client(monkeypatch)
    monkeypatch.setattr(
        tracker.report_agent,
        "request_draft_job_block",
        lambda project_id, job_id, reason: {
            "job_id": job_id,
            "project_id": project_id,
            "status": "blocked",
            "draft_id": "",
            "request": {},
        },
    )
    monkeypatch.setattr(tracker, "_agent_selected_evidence", lambda *args, **kwargs: [])

    response = client.post(
        "/api/agent/projects/rp-1/draft_jobs/dj-1/block",
        headers=headers,
        json={"reason": "manual evidence review required"},
    )

    assert response.status_code == 200
    assert response.get_json()["job"]["status"] == "blocked"


def test_task_control_illegal_transition_returns_stable_conflict(monkeypatch):
    client, headers = _post_client(monkeypatch)
    monkeypatch.setattr(
        tracker.consulting_agent,
        "request_capture_job_block",
        lambda *args: (_ for _ in ()).throw(
            tracker.consulting_agent.InvalidTaskTransitionError(
                "cj-1", "completed", "block_requested"
            )
        ),
    )

    response = client.post(
        "/api/consult/sessions/cs-1/capture_jobs/cj-1/block",
        headers=headers,
    )

    payload = response.get_json()
    assert response.status_code == 409
    assert payload["code"] == "INVALID_TASK_TRANSITION"
    assert payload["details"] == {
        "job_id": "cj-1",
        "current_status": "completed",
        "requested_status": "block_requested",
    }


def test_draft_worker_preserves_first_draft_then_stops_at_cancel_checkpoint(monkeypatch):
    checkpoints = iter(({"status": "running"}, {"status": "cancelled"}))
    saved = []
    updates = []
    monkeypatch.setattr(
        tracker.report_agent,
        "get_draft_job",
        lambda project_id, job_id: {
            "job_id": job_id,
            "project_id": project_id,
            "status": "queued",
            "request": {},
        },
    )
    monkeypatch.setattr(tracker.report_agent, "claim_draft_job", lambda *args: None)
    monkeypatch.setattr(
        tracker.report_agent, "checkpoint_draft_job", lambda *args: next(checkpoints)
    )
    monkeypatch.setattr(
        tracker.report_agent, "get_project", lambda project_id: {"project_id": project_id}
    )
    monkeypatch.setattr(tracker, "_agent_selected_evidence", lambda *args, **kwargs: [])
    monkeypatch.setattr(tracker.report_agent, "build_draft_messages", lambda *args, **kwargs: [])
    monkeypatch.setattr(tracker, "_agent_generation_target", lambda *args: 0)
    monkeypatch.setattr(tracker, "_agent_generation_tokens", lambda *args: 100)
    monkeypatch.setattr(tracker, "_call_ai", lambda *args, **kwargs: "preserved draft")

    def save_draft(*args, **kwargs):
        saved.append((args, kwargs))
        return {"draft_id": "draft-preserved"}

    monkeypatch.setattr(tracker.report_agent, "save_draft", save_draft)
    monkeypatch.setattr(
        tracker.report_agent,
        "update_draft_job",
        lambda job_id, **kwargs: updates.append((job_id, kwargs)),
    )

    tracker._run_agent_draft_job("rp-1", "dj-1")

    assert len(saved) == 1
    assert updates == [("dj-1", {"draft_id": "draft-preserved"})]


def test_capture_cancel_response_is_barrier_for_search_and_asset_writes(monkeypatch):
    state = {"status": "queued"}
    search_entered = threading.Event()
    release_search = threading.Event()
    cancel_requested = threading.Event()
    response_done = threading.Event()
    writes = []
    archive_calls = []
    response_box = {}

    monkeypatch.setattr(
        tracker.consulting_agent,
        "get_capture_job",
        lambda *_args: {
            "job_id": "cj-race",
            "status": state["status"],
            "target_count": 1,
            "batch_size": 1,
            "max_rounds": 1,
            "attempts": [],
        },
    )
    monkeypatch.setattr(
        tracker.consulting_agent,
        "claim_capture_job",
        lambda *_args: state.update(status="running"),
    )
    monkeypatch.setattr(
        tracker.consulting_agent,
        "checkpoint_capture_job",
        lambda *_args: {"status": state["status"]},
    )
    monkeypatch.setattr(
        tracker.consulting_agent,
        "get_session",
        lambda session_id: {"session_id": session_id},
    )
    monkeypatch.setattr(tracker, "_consult_capture_queries", lambda *_args: ["q"])
    monkeypatch.setattr(
        tracker,
        "_consult_capture_counts",
        lambda *_args: {"archived_count": 0},
    )
    monkeypatch.setattr(
        tracker.consulting_agent,
        "capture_asset_counts",
        lambda *_args: {"archived_count": 0},
    )
    monkeypatch.setattr(tracker.consulting_agent, "update_capture_job", lambda *args, **kwargs: None)

    def search(*_args, **_kwargs):
        search_entered.set()
        assert release_search.wait(2)
        return ([{"title": "source", "url": "https://example.test/source"}], {})

    monkeypatch.setattr(tracker.search_adapters, "search_web_multi", search)
    monkeypatch.setattr(
        tracker.consulting_agent,
        "record_query",
        lambda *_args: writes.append("query"),
    )
    monkeypatch.setattr(
        tracker.consulting_agent,
        "upsert_evidence",
        lambda *_args: writes.append("evidence") or [{"evidence_id": "ev-1"}],
    )
    monkeypatch.setattr(
        tracker,
        "_consult_archive_many",
        lambda *_args, **_kwargs: archive_calls.append(True) or [],
    )

    def request_cancel(_session_id, _job_id, _reason):
        state["status"] = "cancel_requested"
        cancel_requested.set()
        return {"job_id": "cj-race", "status": state["status"], "attempts": []}

    monkeypatch.setattr(
        tracker.consulting_agent, "request_capture_job_cancel", request_cancel
    )
    monkeypatch.setattr(tracker, "_consult_enrich_capture_job", lambda _sid, job: job)

    worker = threading.Thread(
        target=tracker._run_consult_capture_job, args=("cs-race", "cj-race")
    )
    worker.start()
    assert search_entered.wait(2)

    def cancel_request():
        client, headers = _post_client(monkeypatch)
        response_box["response"] = client.post(
            "/api/consult/sessions/cs-race/capture_jobs/cj-race/cancel",
            headers=headers,
        )
        response_done.set()

    controller = threading.Thread(target=cancel_request)
    controller.start()
    assert cancel_requested.wait(2)
    assert response_done.is_set() is False
    release_search.set()
    worker.join(2)
    controller.join(2)

    assert response_done.is_set() is True
    assert response_box["response"].status_code == 202
    assert writes == ["query", "evidence"]
    assert archive_calls == []


def test_draft_cancel_response_is_barrier_for_ai_and_draft_write(monkeypatch):
    state = {"status": "queued"}
    ai_entered = threading.Event()
    release_ai = threading.Event()
    cancel_requested = threading.Event()
    draft_saved = threading.Event()
    response_done = threading.Event()
    response_box = {}
    ai_calls = []
    saved = []

    monkeypatch.setattr(
        tracker.report_agent,
        "get_draft_job",
        lambda project_id, job_id: {
            "job_id": job_id,
            "project_id": project_id,
            "status": state["status"],
            "request": {},
        },
    )
    monkeypatch.setattr(
        tracker.report_agent,
        "claim_draft_job",
        lambda *_args: state.update(status="running"),
    )
    monkeypatch.setattr(
        tracker.report_agent,
        "checkpoint_draft_job",
        lambda *_args: {"status": state["status"]},
    )
    monkeypatch.setattr(
        tracker.report_agent,
        "get_project",
        lambda project_id: {"project_id": project_id},
    )
    monkeypatch.setattr(tracker, "_agent_selected_evidence", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(tracker.report_agent, "build_draft_messages", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(tracker, "_agent_generation_target", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(tracker, "_agent_generation_tokens", lambda *_args, **_kwargs: 100)

    def call_ai(*_args, **_kwargs):
        ai_calls.append(True)
        ai_entered.set()
        assert release_ai.wait(2)
        return "preserved draft"

    monkeypatch.setattr(tracker, "_call_ai", call_ai)

    def save_draft(*_args, **_kwargs):
        saved.append(True)
        draft_saved.set()
        return {"draft_id": "draft-race"}

    monkeypatch.setattr(tracker.report_agent, "save_draft", save_draft)
    monkeypatch.setattr(tracker.report_agent, "update_draft_job", lambda *args, **kwargs: None)

    def request_cancel(project_id, job_id, _reason):
        state["status"] = "cancel_requested"
        cancel_requested.set()
        return {
            "job_id": job_id,
            "project_id": project_id,
            "status": state["status"],
            "request": {},
        }

    monkeypatch.setattr(tracker.report_agent, "request_draft_job_cancel", request_cancel)

    worker = threading.Thread(
        target=tracker._run_agent_draft_job, args=("rp-race", "dj-race")
    )
    worker.start()
    assert ai_entered.wait(2)

    def cancel_request():
        client, headers = _post_client(monkeypatch)
        response_box["response"] = client.post(
            "/api/agent/projects/rp-race/draft_jobs/dj-race/cancel",
            headers=headers,
        )
        response_done.set()

    controller = threading.Thread(target=cancel_request)
    controller.start()
    assert cancel_requested.wait(2)
    assert response_done.is_set() is False
    release_ai.set()
    worker.join(2)
    controller.join(2)

    assert draft_saved.is_set() is True
    assert response_done.is_set() is True
    assert response_box["response"].status_code == 202
    assert len(ai_calls) == 1
    assert len(saved) == 1


def test_capture_parser_service_failure_keeps_retryable_code_and_delay(monkeypatch):
    updates = []
    monkeypatch.setattr(
        tracker.consulting_agent,
        "get_capture_job",
        lambda *_args: {
            "job_id": "cj-parser",
            "status": "queued",
            "target_count": 1,
            "batch_size": 1,
            "max_rounds": 1,
            "attempts": [],
            "payload": {"created_from": "test"},
        },
    )
    monkeypatch.setattr(tracker.consulting_agent, "claim_capture_job", lambda *_args: None)
    monkeypatch.setattr(
        tracker.consulting_agent,
        "checkpoint_capture_job",
        lambda *_args: {"status": "running"},
    )
    monkeypatch.setattr(
        tracker.consulting_agent,
        "get_session",
        lambda session_id: {"session_id": session_id},
    )
    monkeypatch.setattr(tracker, "_consult_capture_queries", lambda *_args: ["q"])
    monkeypatch.setattr(
        tracker,
        "_consult_capture_counts",
        lambda *_args: {"archived_count": 0},
    )
    monkeypatch.setattr(
        tracker.consulting_agent,
        "capture_asset_counts",
        lambda *_args: {"archived_count": 0},
    )
    monkeypatch.setattr(
        tracker.consulting_agent,
        "update_capture_job",
        lambda job_id, **kwargs: updates.append((job_id, kwargs)),
    )
    monkeypatch.setattr(
        tracker.search_adapters,
        "search_web_multi",
        lambda *_args, **_kwargs: (
            [{"title": "PDF", "url": "https://example.test/report.pdf"}],
            {},
        ),
    )
    monkeypatch.setattr(tracker.consulting_agent, "record_query", lambda *_args: None)
    monkeypatch.setattr(
        tracker.consulting_agent,
        "upsert_evidence",
        lambda *_args: [{"evidence_id": "ev-pdf"}],
    )
    monkeypatch.setattr(
        tracker.consulting_agent, "list_source_assets", lambda *_args: []
    )
    monkeypatch.setattr(
        tracker,
        "_consult_archive_many",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            tracker.search_adapters.RemoteDocumentError(
                "DOCUMENT_PARSE_QUEUE_FULL",
                "文档解析队列已满，请稍后重试",
                retryable=True,
                details={"retry_after": 5},
            )
        ),
    )

    tracker._run_consult_capture_job("cs-parser", "cj-parser")

    failed = next(kwargs for _job_id, kwargs in updates if kwargs.get("status") == "failed")
    assert failed["error_code"] == "DOCUMENT_PARSE_QUEUE_FULL"
    assert failed["retryable"] is True
    assert failed["payload"] == {
        "created_from": "test",
        "error_details": {"retry_after": 5},
    }
