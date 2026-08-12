"""LLM provider package — Vertex AI only.

This build exclusively uses Google Vertex AI (Claude via ADC auth).
All LLM traffic stays within the configured GCP project. No external
API keys or endpoints are supported.

Required env:
    ANTHROPIC_VERTEX_PROJECT_ID  — GCP project hosting the Claude model
"""

from __future__ import annotations

from .base import ModelMetadataProvider
from .vertex import VertexProvider


def get_metadata_provider() -> ModelMetadataProvider:
    """Return the Vertex provider for token-budget + default-model lookups."""
    return VertexProvider()


# Upstream uses get_active_provider; alias for compatibility
get_active_provider = get_metadata_provider


__all__ = [
    "ModelMetadataProvider",
    "VertexProvider",
    "get_metadata_provider",
    "get_active_provider",
]
