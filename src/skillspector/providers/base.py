"""Protocols for the model metadata provider."""

from __future__ import annotations

from typing import Protocol


class ModelMetadataProvider(Protocol):
    """Provider-side knowledge about models — token budgets and defaults.

    ``get_context_length`` / ``get_max_output_tokens`` return ``None`` to
    signal "I don't know" so callers fall back to defaults.

    ``resolve_model`` runs the per-provider waterfall:
    ``SKILLSPECTOR_MODEL`` env var -> provider's slot-specific default ->
    provider's general default.  Always returns a non-empty string.
    """

    def get_context_length(self, model: str) -> int | None: ...

    def get_max_output_tokens(self, model: str) -> int | None: ...

    def resolve_model(self, slot: str = "default") -> str: ...
