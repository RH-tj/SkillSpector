---
alwaysApply: true
---

# SkillSpector (Vertex AI Fork)

AI agent skill security scanner, forked from [NVIDIA/SkillSpector](https://github.com/NVIDIA/skillspector) and refactored for exclusive use with **Google Vertex AI**. All LLM traffic stays within the configured GCP project; no external API keys or endpoints are used.

## Red Lines

### Data Residency Invariant

**All LLM traffic MUST route through Google Vertex AI within the user's GCP project.** This is the reason this fork exists. Violating this invariant means skill file contents (which may contain internal infrastructure details, credential paths, cluster names, RBAC configurations) are sent to external API endpoints.

Concretely:

1. **Never introduce an alternative LLM provider.** No OpenAI, no Anthropic direct, no NVIDIA `nv_build`, no Bedrock. The only LLM backend is `ChatAnthropicVertex` via `langchain-google-vertexai`.
2. **Never add external API key support.** Authentication is Google ADC only (`gcloud auth application-default login`). No `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `NV_API_KEY`, or similar env vars.
3. **All new LLM-calling code must use `get_chat_model()` from `skillspector.llm_utils`.** Do not import LLM clients directly.

### Prohibited Imports

Never add these imports anywhere in `src/skillspector/`:

```python
# PROHIBITED — these send data outside the GCP project
from langchain_openai import ...
from langchain_anthropic import ...      # (non-Vertex Anthropic)
from openai import ...
import anthropic
from langchain_community.chat_models import ...
```

The only permitted LLM import is:

```python
from skillspector.llm_utils import get_chat_model, chat_completion, is_llm_available
```

### Prohibited Environment Variables

Never reference these as LLM configuration:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `NV_API_KEY` / `NVIDIA_API_KEY`
- `OPENAI_BASE_URL`

The only LLM-related env vars are:

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_VERTEX_PROJECT_ID` | GCP project hosting the Claude model on Vertex AI (required for LLM analysis) |
| `CLOUD_ML_REGION` | Vertex AI region (default: `global`) |
| `SKILLSPECTOR_MODEL` | Override default model (default: `claude-opus-4-6`) |
| `SKILLSPECTOR_MODEL_{SLOT}` | Per-analyzer model override |
| `SKILLSPECTOR_LOG_LEVEL` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

## Repository Structure

| Path | Purpose |
|------|---------|
| `src/skillspector/` | Main package |
| `src/skillspector/providers/vertex/` | Vertex AI provider (fork-only) |
| `src/skillspector/providers/__init__.py` | Provider registry (Vertex-only) |
| `src/skillspector/llm_utils.py` | LLM client factory — single entry point for all LLM calls |
| `src/skillspector/rate_limiter.py` | Adaptive rate limiter (fork-only) |
| `src/skillspector/nodes/analyzers/` | Static pattern analyzers (additive, safe to extend) |
| `src/skillspector/nodes/meta_analyzer.py` | LLM semantic analysis (heavily modified) |
| `src/skillspector/nodes/` | LangGraph pipeline nodes |
| `tests/` | Test suite |
| `docs/` | Architecture and development documentation |

## Protected Files

These files contain the fork's core modifications. **Never overwrite them with upstream content.** When upstream changes touch these files, manually read the upstream diff and port only the relevant logic.

- `src/skillspector/providers/` — entire directory, especially `vertex/`, `__init__.py`, `base.py`
- `src/skillspector/llm_utils.py` — Vertex-only LLM client factory
- `src/skillspector/llm_analyzer_base.py` — rate limiter integration
- `src/skillspector/rate_limiter.py` — fork-only adaptive semaphore
- `src/skillspector/nodes/meta_analyzer.py` — JSON parsing, severity-gated floor, batch failure isolation, confidence normalization, LLM degradation surfacing
- `src/skillspector/state.py` — `llm_call_log` and `llm_call_record()` for degradation tracking
- `src/skillspector/cli.py` — Vertex-specific CLI defaults
- `pyproject.toml` — fork dependency tree (`langchain-google-vertexai`)
- `uv.lock` — regenerated from fork's `pyproject.toml`
- `README.md` — completely rewritten for the fork

## Writing New LLM-Calling Code

When adding a new analyzer or feature that needs LLM analysis:

```python
from skillspector.llm_utils import get_chat_model
from skillspector.rate_limiter import rate_limited_ainvoke

llm = get_chat_model()
response = await rate_limited_ainvoke(llm, prompt)
```

Key requirements:

1. **Use `get_chat_model()`** — never construct `ChatAnthropicVertex` directly outside `llm_utils.py`.
2. **Use `rate_limited_ainvoke` / `rate_limited_invoke`** from `rate_limiter.py` — never call `llm.invoke()` or `llm.ainvoke()` directly. The rate limiter manages concurrency across all analyzers.
3. **Handle JSON parsing defensively** — Vertex AI responses may arrive as raw text with markdown fences or partial JSON. Use the JSON extraction patterns from `meta_analyzer.py` as a reference.
4. **Subclass `LLMAnalyzerBase`** from `llm_analyzer_base.py` for discovery-mode analyzers — it handles file chunking, token budgeting, and rate limiting automatically.

## Development Commands

```bash
uv venv .venv && source .venv/bin/activate
make install-dev          # install with dev dependencies
make test                 # run full test suite
make lint                 # run linting
make format               # auto-format code
```

### Known Test Exclusions

These test files have pre-existing import failures and are excluded from the test baseline:

- `tests/unit/test_llm_utils.py` — references upstream multi-provider API
- `tests/unit/test_providers.py` — references removed upstream providers

When running tests, exclude them: `pytest --ignore=tests/unit/test_llm_utils.py --ignore=tests/unit/test_providers.py`

A passing test run should match the baseline failure count on `main`. If new tests fail after your change, investigate before committing.

## Upstream Sync

See the [Development Guide — Syncing with Upstream](README.md#development-guide--syncing-with-upstream) section in `README.md` for the full cherry-pick workflow, protected files table, and classification criteria.

**Key rule:** upstream commits that add new LLM providers or modify `providers/__init__.py` to register non-Vertex backends must be **skipped entirely**.
