import os

import pytest

# 生产默认为强制鉴权。测试套件显式进入本地开发模式，避免
# 大量与鉴权无关的旧路由因会话守卫而失真。鉴权本身有独立负面测试。
os.environ["ACCESS_TOKEN_REQUIRED"] = "0"
os.environ.pop("DEFENSE_TRACKER_DESKTOP_BOOTSTRAP", None)

from state import _rate_lock, _rate_store


@pytest.fixture(autouse=True)
def isolate_process_local_rate_limits():
    """Keep production rate-limit semantics while isolating independent tests."""
    with _rate_lock:
        _rate_store.clear()
    yield
    with _rate_lock:
        _rate_store.clear()
