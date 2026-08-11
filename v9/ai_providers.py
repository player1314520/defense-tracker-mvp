"""Versioned allowlist for user-supplied AI credentials.

The caller selects a provider and model identifier. Network destinations are
always returned from this module; no caller-supplied URL crosses this boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


REGISTRY_VERSION = "2026-08-09"


class UnsupportedAiProvider(ValueError):
    """A provider, model or registry version is outside the fixed allowlist."""


@dataclass(frozen=True, slots=True)
class AiProviderSelection:
    provider: str
    model_id: str
    endpoint: str
    registry_version: str


@dataclass(frozen=True, slots=True)
class _ProviderDefinition:
    endpoint: str
    models: frozenset[str]


_PROVIDERS = MappingProxyType({
    "deepseek": _ProviderDefinition(
        endpoint="https://api.deepseek.com/chat/completions",
        models=frozenset({"deepseek-v4-flash", "deepseek-v4-pro"}),
    ),
    "zhipu": _ProviderDefinition(
        endpoint="https://open.bigmodel.cn/api/paas/v4/chat/completions",
        models=frozenset({"glm-5.2", "glm-5-turbo"}),
    ),
    "moonshot": _ProviderDefinition(
        endpoint="https://api.moonshot.cn/v1/chat/completions",
        models=frozenset({"kimi-k3", "kimi-k2.6"}),
    ),
})


def resolve_provider(
    provider: str,
    model_id: str,
    *,
    registry_version: str = REGISTRY_VERSION,
) -> AiProviderSelection:
    """Resolve a fixed provider/model pair to its official HTTPS endpoint."""
    if registry_version != REGISTRY_VERSION:
        raise UnsupportedAiProvider("unsupported AI provider registry version")
    provider_name = str(provider or "").strip().lower()
    model_name = str(model_id or "").strip()
    definition = _PROVIDERS.get(provider_name)
    if definition is None or model_name not in definition.models:
        raise UnsupportedAiProvider("unsupported AI provider or model")
    return AiProviderSelection(
        provider=provider_name,
        model_id=model_name,
        endpoint=definition.endpoint,
        registry_version=REGISTRY_VERSION,
    )


def provider_catalog() -> tuple[dict[str, object], ...]:
    """Return public, credential-free provider metadata for selection UIs."""
    return tuple(
        {
            "provider": name,
            "models": tuple(sorted(definition.models)),
            "registry_version": REGISTRY_VERSION,
        }
        for name, definition in _PROVIDERS.items()
    )
