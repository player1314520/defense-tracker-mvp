from __future__ import annotations

import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

import app as tracker
import consulting_agent


def _browser_executable() -> Path | None:
    candidates = (
        Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
        Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    )
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def test_archived_html_cannot_execute_or_reach_same_origin_api(monkeypatch, tmp_path):
    playwright = pytest.importorskip("playwright.sync_api")
    browser_executable = _browser_executable()
    if browser_executable is None:
        pytest.skip("Edge or Chrome is required for the archived-asset attack probe")

    monkeypatch.setattr(
        consulting_agent,
        "CONSULTING_AGENT_DB_FILE",
        str(tmp_path / "consult.sqlite3"),
    )
    monkeypatch.setattr(
        consulting_agent,
        "SOURCE_ARCHIVE_DIR",
        str(tmp_path / "source_archive"),
        raising=False,
    )
    tracker.app.config["TESTING"] = True

    session = consulting_agent.create_session("恶意归档浏览器隔离测试")
    evidence = consulting_agent.upsert_evidence(
        session["session_id"],
        [
            {
                "title": "Untrusted HTML",
                "source": "Untrusted Source",
                "url": "https://example.test/untrusted.html",
                "channel": "web",
                "score": 80,
                "snippet": "Untrusted browser payload.",
            }
        ],
    )[0]
    payload = b"""<!doctype html><html><body>
<script>parent.postMessage('asset_probe_script', '*');fetch('/api/status?asset_probe=script&csrf='+encodeURIComponent(document.cookie))</script>
<img src=x onerror="parent.postMessage('asset_probe_onerror','*');fetch('/api/status?asset_probe=onerror&csrf='+encodeURIComponent(document.cookie))">
</body></html>"""
    asset = consulting_agent.archive_source_asset(
        session["session_id"],
        evidence,
        {
            "title": "Untrusted HTML",
            "url": evidence["url"],
            "text": payload.decode("utf-8"),
            "document_type": "html",
            "content_type": "text/html",
            "raw_bytes": payload,
            "is_fetched_original": True,
        },
    )

    server = make_server("127.0.0.1", 0, tracker.app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    preview_url = (
        f"{base_url}/api/consult/sessions/{session['session_id']}"
        f"/assets/{asset['asset_id']}/preview"
    )

    try:
        with playwright.sync_playwright() as runtime:
            browser = runtime.chromium.launch(
                executable_path=str(browser_executable),
                headless=True,
                args=[f"--explicitly-allowed-ports={server.server_port}"],
            )
            context = browser.new_context(accept_downloads=True)
            context.add_init_script(
                "localStorage.setItem('defense_hub_v9_onboarded', '1')"
            )
            page = context.new_page()
            marker_requests: list[str] = []
            dialogs: list[str] = []
            page_errors: list[str] = []

            page.on(
                "request",
                lambda request: (
                    marker_requests.append(request.url)
                    if "asset_probe" in request.url
                    else None
                ),
            )

            def dismiss_dialog(dialog):
                dialogs.append(dialog.message)
                dialog.dismiss()

            page.on("dialog", dismiss_dialog)
            page.on("pageerror", lambda error: page_errors.append(str(error)))
            page.goto(base_url, wait_until="domcontentloaded", timeout=30_000)
            page.wait_for_timeout(1_000)

            preview = page.evaluate(
                "url => fetch(url, {credentials: 'same-origin'}).then(r => r.json())",
                preview_url,
            )
            assert preview["preview_mode"] == "document"
            assert preview["file_is_real_pdf"] is False
            assert preview["file_url"].endswith(f"/assets/{asset['asset_id']}/file")

            page.evaluate("data => consultRenderAssetPreview(data)", preview)
            assert page.locator("#consultAssetPreview img").count() == 0
            assert page.locator("#consultAssetPreview script").count() == 0

            page.evaluate(
                """url => {
                    window.__assetProbeMessages = [];
                    window.addEventListener('message', event => {
                        if (String(event.data).startsWith('asset_probe_')) {
                            window.__assetProbeMessages.push(String(event.data));
                        }
                    });
                    const frame = document.createElement('iframe');
                    frame.id = 'assetProbeFrame';
                    frame.src = url;
                    document.body.appendChild(frame);
                }""",
                base_url + preview["file_url"],
            )
            page.wait_for_timeout(1_500)

            assert page.evaluate("window.__assetProbeMessages") == []
            assert marker_requests == []
            assert dialogs == []
            assert page_errors == []

            with page.expect_download(timeout=10_000) as download_info:
                with pytest.raises(playwright.Error, match="Download is starting"):
                    page.goto(base_url + preview["download_url"])
            assert download_info.value.suggested_filename == "original.html"

            context.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
