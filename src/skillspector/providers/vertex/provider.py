"""Vertex AI provider — Claude models via Google Cloud (ADC auth).

Authenticates using Google Application Default Credentials. No API keys
are stored or transmitted. All LLM traffic stays within the configured
GCP project.

Required env:
    ANTHROPIC_VERTEX_PROJECT_ID  — GCP project hosting the Claude model
Optional env:
    CLOUD_ML_REGION              — Vertex AI region (default: "global")
    SKILLSPECTOR_MODEL           — override default model label
"""

from __future__ import annotations

import os
from pathlib import Path

from skillspector.providers import registry

REGISTRY_PATH = str(Path(__file__).with_name("model_registry.yaml"))


class VertexProvider:
    """Vertex AI credentials + bundled-YAML metadata provider."""

    DEFAULT_MODEL = "claude-sonnet-4-6"
    SLOT_DEFAULTS: dict[str, str] = {
        "meta_analyzer": "claude-sonnet-4-6",
    }

    @property
    def project_id(self) -> str:
        val = os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", "").strip()
        if not val:
            raise ValueError(
                "ANTHROPIC_VERTEX_PROJECT_ID must be set for the Vertex provider."
            )
        return val

    @property
    def region(self) -> str:
        return os.environ.get("CLOUD_ML_REGION", "global").strip()

    def get_context_length(self, model: str) -> int | None:
        return registry.lookup_context_length(REGISTRY_PATH, model)

    def get_max_output_tokens(self, model: str) -> int | None:
        return registry.lookup_max_output_tokens(REGISTRY_PATH, model)

    def resolve_model(self, slot: str = "default") -> str:
        user_input = os.environ.get("SKILLSPECTOR_MODEL", "").strip()
        return user_input or self.SLOT_DEFAULTS.get(slot, "") or self.DEFAULT_MODEL
