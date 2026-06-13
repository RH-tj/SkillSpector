"""LLM utilities — Vertex AI only (ChatAnthropicVertex via Google ADC).

All LLM traffic is routed exclusively through Google Vertex AI within
the GCP project specified by ANTHROPIC_VERTEX_PROJECT_ID. No external
API keys (OpenAI, Anthropic direct, NVIDIA) are supported.
"""

from __future__ import annotations

import os

from langchain_google_vertexai.model_garden import ChatAnthropicVertex

from skillspector.constants import MODEL_CONFIG
from skillspector.model_info import get_max_input_tokens, get_max_output_tokens
from skillspector.providers import get_metadata_provider


def _get_project_id() -> str:
    val = os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", "").strip()
    if not val:
        raise ValueError(
            "ANTHROPIC_VERTEX_PROJECT_ID must be set. "
            "Use --no-llm to skip LLM analysis and run static checks only."
        )
    return val


def _get_region() -> str:
    return os.environ.get("CLOUD_ML_REGION", "global").strip()


def is_llm_available() -> tuple[bool, str | None]:
    """Return (available, error_message) describing LLM readiness."""
    project = os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", "").strip()
    if not project:
        return False, (
            "ANTHROPIC_VERTEX_PROJECT_ID is not set. "
            "Set it to your GCP project ID to enable LLM analysis, "
            "or use --no-llm for static-only scanning."
        )
    return True, None


def fetch_model_token_limits(model_label: str) -> tuple[int, int]:
    """Return (max_input_tokens, max_output_tokens) for model_label."""
    return get_max_input_tokens(model_label), get_max_output_tokens(model_label)


def get_chat_model(model: str | None = None) -> ChatAnthropicVertex:
    """Return a ChatAnthropicVertex configured for the GCP Vertex project.

    Authenticates via Google Application Default Credentials (ADC).
    All traffic stays within the configured GCP project.
    """
    model = model or MODEL_CONFIG["default"]

    return ChatAnthropicVertex(
        model_name=model,
        project=_get_project_id(),
        location=_get_region(),
        max_output_tokens=get_max_output_tokens(model),
    )


def chat_completion(prompt: str, *, model: str | None = None) -> str:
    """Request a single chat completion and return the assistant content."""
    llm = get_chat_model(model=model)
    response = llm.invoke(prompt)
    return response.content or ""
