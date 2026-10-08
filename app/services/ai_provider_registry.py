"""AI Provider Registry — provider-agnostic configuration layer.

Defines all supported AI providers with their metadata, default base URLs,
protocol type, and whether they use the OpenAI-compatible chat/completions
format.

This module is the single source of truth for:
  - Which providers are available in the dashboard UI
  - Default base URLs for each provider
  - Whether a provider uses OpenAI-compatible endpoints
  - Whether model discovery is supported

SECURITY: This module contains NO credentials — only public metadata.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AIProviderDefinition:
    """Definition of a supported AI provider.

    Attributes:
        id:                 Unique provider identifier (stored in vault metadata).
        display_name:       Human-readable name shown in the dashboard UI.
        protocol:           "openai_compatible" or "native" (needs adapter).
        default_base_url:   Pre-filled base URL when user selects this provider.
        api_key_label:      Label for the API key field (e.g. "API Key", "Secret Key").
        supports_custom_base_url:  Whether user can override the base URL.
        supports_model_discovery:  Whether /models endpoint is available.
        default_model:      Pre-filled model when user selects this provider.
        adapter_ready:      Whether the backend adapter is implemented.
        help_text:          Optional help text shown in the UI for this provider.
    """
    id: str
    display_name: str
    protocol: str  # "openai_compatible" | "native"
    default_base_url: str
    api_key_label: str = "API Key"
    supports_custom_base_url: bool = True
    supports_model_discovery: bool = True
    default_model: str = ""
    adapter_ready: bool = True
    help_text: str = ""


# ── Provider Registry ────────────────────────────────────────────────────

PROVIDERS: dict[str, AIProviderDefinition] = {
    "openai": AIProviderDefinition(
        id="openai",
        display_name="OpenAI",
        protocol="openai_compatible",
        default_base_url="https://api.openai.com/v1",
        supports_custom_base_url=False,
        default_model="gpt-4o",
        help_text="Uses the OpenAI Chat Completions API.",
    ),
    "anthropic": AIProviderDefinition(
        id="anthropic",
        display_name="Anthropic / Claude",
        protocol="native",
        default_base_url="https://api.anthropic.com",
        api_key_label="API Key",
        supports_custom_base_url=False,
        default_model="claude-sonnet-4-5-20250514",
        adapter_ready=False,
        help_text="Configuration supported; runtime adapter pending.",
    ),
    "gemini": AIProviderDefinition(
        id="gemini",
        display_name="Google Gemini",
        protocol="native",
        default_base_url="https://generativelanguage.googleapis.com/v1beta",
        api_key_label="API Key",
        supports_custom_base_url=False,
        default_model="gemini-2.5-pro",
        adapter_ready=False,
        help_text="Configuration supported; runtime adapter pending.",
    ),
    "xai": AIProviderDefinition(
        id="xai",
        display_name="xAI / Grok",
        protocol="openai_compatible",
        default_base_url="https://api.x.ai/v1",
        default_model="grok-4",
        help_text="Uses the OpenAI-compatible Chat Completions API.",
    ),
    "moonshot": AIProviderDefinition(
        id="moonshot",
        display_name="Moonshot / Kimi",
        protocol="openai_compatible",
        default_base_url="https://api.moonshot.cn/v1",
        default_model="moonshot-v1-8k",
        help_text="Uses the OpenAI-compatible Chat Completions API.",
    ),
    "openrouter": AIProviderDefinition(
        id="openrouter",
        display_name="OpenRouter",
        protocol="openai_compatible",
        default_base_url="https://openrouter.ai/api/v1",
        default_model="openai/gpt-4o",
        help_text="Routes to 200+ models. Use provider/model format (e.g. openai/gpt-4o).",
    ),
    "tokenrouter": AIProviderDefinition(
        id="tokenrouter",
        display_name="TokenRouter",
        protocol="openai_compatible",
        default_base_url="https://api.tokenrouter.com/v1",
        default_model="",
        help_text="Uses the OpenAI-compatible Chat Completions API.",
    ),
    "custom_openai_compatible": AIProviderDefinition(
        id="custom_openai_compatible",
        display_name="Custom OpenAI-Compatible",
        protocol="openai_compatible",
        default_base_url="",
        supports_custom_base_url=True,
        supports_model_discovery=False,
        default_model="",
        help_text="Any endpoint that implements the OpenAI /chat/completions API.",
    ),
}


def get_provider(provider_id: str) -> AIProviderDefinition | None:
    """Return the provider definition, or None if unknown."""
    return PROVIDERS.get(provider_id)


def get_all_providers() -> list[AIProviderDefinition]:
    """Return all registered providers in display order."""
    return list(PROVIDERS.values())


def get_provider_ids() -> list[str]:
    """Return all registered provider IDs."""
    return list(PROVIDERS.keys())


def is_openai_compatible(provider_id: str) -> bool:
    """Return True if the provider uses the OpenAI chat/completions format."""
    provider = PROVIDERS.get(provider_id)
    return provider is not None and provider.protocol == "openai_compatible"


def normalize_chat_completions_url(base_url: str) -> str:
    """Normalize a base URL to ensure it ends with /chat/completions.

    Handles:
      - "https://example.com/v1"           → "https://example.com/v1/chat/completions"
      - "https://example.com/v1/"          → "https://example.com/v1/chat/completions"
      - "https://example.com/v1/chat/completions" → "https://example.com/v1/chat/completions" (no double)
      - "https://example.com/v1/chat/completions/" → "https://example.com/v1/chat/completions" (strip trailing slash)
    """
    url = base_url.rstrip("/")
    if url.endswith("/chat/completions"):
        return url
    if url.endswith("/chat"):
        return url + "/completions"
    return url + "/chat/completions"
