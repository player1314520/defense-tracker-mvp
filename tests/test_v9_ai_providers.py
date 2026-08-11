# -*- coding: utf-8 -*-

import pytest


def test_registry_resolves_only_fixed_official_https_endpoints():
    from v9.ai_providers import REGISTRY_VERSION, resolve_provider

    expected = {
        ("deepseek", "deepseek-v4-pro"):
            "https://api.deepseek.com/chat/completions",
        ("zhipu", "glm-5.2"):
            "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        ("moonshot", "kimi-k3"):
            "https://api.moonshot.cn/v1/chat/completions",
    }

    for (provider, model_id), endpoint in expected.items():
        resolved = resolve_provider(provider, model_id)
        assert resolved.provider == provider
        assert resolved.model_id == model_id
        assert resolved.endpoint == endpoint
        assert resolved.registry_version == REGISTRY_VERSION
        assert resolved.endpoint.startswith("https://")


@pytest.mark.parametrize(
    ("provider", "model_id"),
    [
        ("openai", "gpt-5"),
        ("deepseek", "deepseek-chat"),
        ("zhipu", "custom-glm"),
        ("moonshot", "moonshot-v1-8k"),
    ],
)
def test_registry_rejects_unknown_provider_or_model(provider, model_id):
    from v9.ai_providers import UnsupportedAiProvider, resolve_provider

    with pytest.raises(UnsupportedAiProvider):
        resolve_provider(provider, model_id)


def test_registry_version_is_explicit_and_fail_closed():
    from v9.ai_providers import UnsupportedAiProvider, resolve_provider

    with pytest.raises(UnsupportedAiProvider, match="registry version"):
        resolve_provider(
            "deepseek",
            "deepseek-v4-pro",
            registry_version="untrusted-future-version",
        )


def test_resolver_has_no_custom_base_url_surface():
    from inspect import signature

    from v9.ai_providers import resolve_provider

    assert "base_url" not in signature(resolve_provider).parameters
