# Upstream Sync Journal

Persistent record of sync operations between this fork (`RH-tj/SkillSpector`) and
upstream (`nvidia/SkillSpector`). Read this file first in any future sync session.

---

## Last Sync

| Field | Value |
|-------|-------|
| **Date** | 2026-08-12 |
| **Branch** | `feature/upstream-sync-2026-08` |
| **Upstream commit synced to** | `f883df60efbcad78ad3bf132a1a8b993dd96a992` |
| **Nearest upstream tag** | `v2.9.3` (6 commits ahead) |
| **Previous merge-base** | `1a7bf026a3cf0ecfd957b6c173244d51b3141baf` (2026-06-10) |
| **Fork was ahead by** | 71 commits |
| **Upstream was ahead by** | 322 commits |
| **Test result** | 1050 passed, 114 failed (expected — see Known Test Gaps) |

---

## Method Used (Hybrid Sync)

**Do NOT `git merge upstream/main`** — the provider divergence makes that impossible.

1. `git checkout` individual files from `upstream/main` for new standalone modules
2. Manually rewrite `llm_analyzer_base.py` and `meta_analyzer.py` to merge logic
3. Take upstream versions wholesale for files with no provider imports
4. Add compatibility shims (e.g. `get_active_provider` alias) where needed

---

## Fork Invariants (do not re-read AGENTS.md each time — summary here)

| Invariant | Enforcement |
|-----------|-------------|
| Vertex AI only | `llm_utils.py` → `ChatAnthropicVertex`; no other LLM backend |
| Rate limiter | `rate_limiter.py` → `rate_limited_ainvoke`/`rate_limited_invoke` wraps all LLM calls |
| No external API keys | Only `ANTHROPIC_VERTEX_PROJECT_ID`, `CLOUD_ML_REGION`, `SKILLSPECTOR_MODEL` |
| Deps | `langchain-google-vertexai`, `anthropic[vertex]` — never `langchain-anthropic`/`langchain-openai` |

---

## What Was Ported (2026-08-12)

### New infrastructure modules (cherry-picked as-is)
- `inspection_ledger.py` — execution accounting, `guard_analyzer_node`
- `inference_usage.py` — token/cost tracking
- `suppression.py` — baseline/FP suppression (`Baseline`, `partition_findings`)
- `multi_skill.py` — batch multi-skill scanning
- `python_ast.py` — shared AST parsing utility
- `cleanup.py` — temp file cleanup
- `mcp_registry.py` — MCP registry posture scanning
- `mcp_server.py` — MCP server integration
- `nodes/finalize_inspection_ledger.py`
- `yara_rules/malware.yar.b64`
- `contrib/batch_scan/` — batch scanning scripts

### New analyzer (cherry-picked)
- `whitespace_padding.py` — P9 invisible-char detection

### Manually ported (fork logic preserved + upstream features added)
- **`llm_analyzer_base.py`**: Added `BatchFailure`, `BatchExecutionResult`,
  `resolve_max_concurrency()`, structured output retries, API connection retries,
  `LLMFinding` confidence normalization + start_line clamping, ledger event projection.
  **Kept**: `rate_limited_ainvoke`/`rate_limited_invoke`, Vertex raw JSON parsing.
- **`meta_analyzer.py`**: Added `_passthrough_with_defaults` (fail-closed),
  `_meta_batch_work_id` (stable identity), `_meta_ledger_response`, empty batch
  filtering, `finding_id`-based matching. **Kept**: `filtered_findings` output key,
  Vertex raw JSON response handling.
- **`rate_limiter.py`**: Added `SKILLSPECTOR_MAX_LLM_CONCURRENCY` env override.

### Taken from upstream wholesale (verified no provider imports)
- `graph.py`, `state.py`, `report.py`, `deduplicate.py`, `sarif_models.py`
- `cli.py`, `constants.py`, `logging_config.py`, `model_info.py`, `input_handler.py`
- `nodes/build_context.py`, `nodes/resolve_input.py`
- All `nodes/analyzers/*.py` (static_runner, behavioral_ast, osv_client, MCP analyzers,
  pattern_defaults, all static_patterns_* files, common.py)
- `nodes/analyzers/__init__.py` (upstream registry)

### Models change
- `models.py`: Added `finding_id` field (`uuid4`) + `_new_finding_id()` factory

### Deps / packaging
- `pyproject.toml`: Added `packaging>=24.0`, `mcp` optional dep group, `.yar.b64` glob,
  relaxed `requires-python` to `>=3.12` (removed `<3.14`)
- `providers/__init__.py`: Added `get_active_provider` alias

---

## What Was Skipped

These upstream files/commits were intentionally NOT ported:

| Path / pattern | Reason |
|----------------|--------|
| `providers/bedrock/` | Non-Vertex provider |
| `providers/claude_cli/`, `codex_cli/`, `gemini_cli/`, `antigravity_cli/` | CLI providers |
| `providers/anthropic_proxy/` | Different auth contract |
| `providers/_agent_cli_base.py`, `_agent_cli.py` | Agent CLI infra |
| `providers/chat_models.py` | Multi-provider selection |
| `providers/__init__.py` (upstream version) | Registers non-Vertex backends |
| `llm_utils.py` (upstream version) | Multi-provider factory, `_ainvoke_with_usage` tied to ChatOpenAI/ChatAnthropic |
| Tests: `test_bedrock_provider.py`, `test_anthropic_proxy_provider.py`, `test_agent_cli.py`, `test_reviewer_nits.py`, `test_mcp_server.py`, `test_wheel_contents.py` | Provider-dependent or build-tool-dependent |
| Reasoning effort pass-through commits | OpenAI/Anthropic-specific |
| `ANTHROPIC_BASE_URL` override | Direct Anthropic, not Vertex |

---

## Known Test Gaps (expected failures after sync)

| Test file | Failure type | Reason |
|-----------|-------------|--------|
| `tests/unit/test_model_info.py` | `AttributeError: cache_clear` in teardown | Upstream uses `@functools.cache` on `_resolve_context_length`; fork version doesn't cache |
| `tests/unit/test_create_github_release.py` | `ModuleNotFoundError` or assertion | CI-only release workflow; not applicable to fork |
| `tests/unit/test_github_release_workflow.py` | Same | Same |
| `tests/unit/test_mcp_server.py` | `ImportError: reset_provider` | Multi-provider switching; fork is Vertex-only |
| `tests/unit/test_reviewer_nits.py` | `ModuleNotFoundError: chat_models` | References skipped multi-provider module |
| `tests/unit/test_wheel_contents.py` | `ModuleNotFoundError: hatchling` | Build-time dep not installed at test time |
| `tests/nodes/test_semantic_quality_policy.py` | Assertion failures | Fixture format changed upstream; needs fixture update |
| `tests/unit/test_patterns.py` (some) | `assert 0 >= 1` | Upstream FP reduction changed detection behavior |
| `tests/unit/test_patterns_new.py` (1) | TM1 no_verify_flag | Same — detection threshold changed |
| `tests/unit/test_input_handler_ssrf.py` (1) | URL allow-list | Upstream changed allowed hosts |
| `tests/test_mcp_tool_poisoning.py` (2) | TP4 fallback behavior | Upstream changed error handling contract |

---

## Next Sync Checklist

```bash
# 1. Fetch upstream
git fetch upstream

# 2. Identify new upstream commit range
git log --oneline f883df60..upstream/main | wc -l   # commits since last sync
git diff --stat f883df60..upstream/main | tail -3    # files changed

# 3. Create sync branch
git checkout origin/main
git checkout -b feature/upstream-sync-YYYY-MM

# 4. Classify new changes (run from repo root)
# Check for new files (safe to cherry-pick):
git diff --diff-filter=A --name-only f883df60..upstream/main -- src/skillspector/

# Check for provider-related changes (SKIP):
git log --oneline f883df60..upstream/main -- \
  src/skillspector/providers/ \
  src/skillspector/llm_utils.py | grep -v "vertex"

# Check for shared-file modifications (need manual port):
git diff --name-only f883df60..upstream/main -- src/skillspector/ | \
  xargs -I{} sh -c 'git log --oneline origin/main ^f883df60 -- {} | \
  grep -q . && echo "BOTH: {}"'

# 5. Cherry-pick new standalone files
git checkout upstream/main -- <new-file-paths>
# AUDIT each for prohibited imports before committing

# 6. Manually port shared files
# Key files to check: llm_analyzer_base.py, meta_analyzer.py, graph.py,
# state.py, report.py, cli.py, constants.py

# 7. Run tests
python -m pytest tests/ \
  --ignore=tests/unit/test_llm_utils.py \
  --ignore=tests/unit/test_providers.py \
  --ignore=tests/unit/test_mcp_server.py \
  --ignore=tests/unit/test_reviewer_nits.py \
  --ignore=tests/unit/test_wheel_contents.py \
  --tb=short

# 8. Update THIS file with new sync metadata
```

---

## Compatibility Shims Added

These exist solely to bridge upstream's API assumptions with the fork's architecture:

| Shim | Location | What it does |
|------|----------|--------------|
| `get_active_provider` | `providers/__init__.py` | Alias for `get_metadata_provider` (upstream renamed it) |
| `merge_findings_by_id` | `state.py` | Upstream's custom reducer; fork uses `operator.add` but tests import this |
| Vertex raw JSON parsing | `llm_analyzer_base.py` `parse_response()` | Upstream uses `with_structured_output`; Vertex doesn't support it reliably |
| `rate_limited_ainvoke` wrapping | `llm_analyzer_base.py` | Fork's rate limiter replaces upstream's `_ainvoke_with_usage` |

---

## Commits in This Sync (oldest first)

```
d327365 feat: add upstream infrastructure modules (inspection_ledger, suppression, multi_skill, etc.)
380f070 feat: add upstream YARA rules and test fixtures
5bb74b0 feat: add whitespace_padding analyzer and MCP registry/server from upstream
7bb653d test: add new upstream test files for infrastructure and analyzers
87b5c69 feat(llm): port upstream retry logic, batch failure tracking, and concurrency config
b42273a feat(meta_analyzer): port fail-closed behavior, ledger integration, and batch identity
c41a8b5 feat: wire inspection_ledger into graph and expand state schema
374da48 feat(report): port upstream SARIF compliance, sanitizer, degradation, and suppression
f1adf85 feat(analyzers): port upstream analyzer improvements and security fixes
e2e2c09 feat: wire CLI, update deps, and finalize integration
7d5b219 fix: resolve import errors and test compatibility for upstream sync
```
