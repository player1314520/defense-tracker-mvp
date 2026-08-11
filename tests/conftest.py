import pytest

from state import _rate_lock, _rate_store


@pytest.fixture(autouse=True)
def isolate_process_local_rate_limits():
    """Keep production rate-limit semantics while isolating independent tests."""
    with _rate_lock:
        _rate_store.clear()
    yield
    with _rate_lock:
        _rate_store.clear()
