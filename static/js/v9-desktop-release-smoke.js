(() => {
  'use strict';
  const endpoint = '/_internal/v9/desktop-release-smoke';
  const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
  const send = async () => {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        const response = await fetch('/api/status', {
          credentials: 'same-origin', cache: 'no-store'
        });
        const payload = await response.json().catch(() => ({}));
        const evidence = {
          schema: 1,
          http_status: response.status,
          pathname: window.location.pathname,
          workspace_ready: Boolean(document.querySelector('main.v9-workspace')),
          version: payload.version,
          display_version: payload.display_version,
          release_tag: payload.release_tag,
          build_commit: payload.build_commit
        };
        if (!response.ok || evidence.pathname !== '/' || !evidence.workspace_ready) throw new Error();
        if (typeof evidence.version !== 'string' || typeof evidence.display_version !== 'string' ||
            typeof evidence.release_tag !== 'string' ||
            !/^[0-9a-f]{40}$/.test(evidence.build_commit)) throw new Error();
        if (typeof payload.csrf_token !== 'string' || !payload.csrf_token) throw new Error();
        const submitted = await fetch(endpoint, {
          method: 'POST', credentials: 'same-origin', cache: 'no-store',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': payload.csrf_token },
          body: JSON.stringify(evidence)
        });
        if (submitted.status === 204) return;
      } catch (_) {}
      if (attempt < 4) await delay(150 * (attempt + 1));
    }
  };
  send();
})();
