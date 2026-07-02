# SkillSpector (Vertex AI Fork)

> **Fork of [NVIDIA/SkillSpector](https://github.com/NVIDIA/skillspector)** — refactored to use **Google Vertex AI exclusively** for LLM analysis. All LLM traffic stays within your GCP project; no external API keys or endpoints are used.

**Security scanner for AI agent skills.** Detect vulnerabilities, malicious patterns, and security risks before installing agent skills.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## Fork Changes

This fork replaces all three upstream LLM provider backends (OpenAI, Anthropic direct, NVIDIA `nv_build`) with a single **Google Vertex AI** provider.

### Why

Skill files often contain internal infrastructure details (URLs, credential paths, cluster names, RBAC configurations). Sending these to external LLM APIs may violate data residency or handling requirements. This fork ensures skill contents are only processed within your own GCP project boundary.

### What Changed

| Aspect | Upstream (NVIDIA) | This Fork |
|--------|-------------------|-----------|
| LLM providers | OpenAI, Anthropic, NVIDIA | **Vertex AI only** |
| Authentication | API keys via env vars | **Google ADC** (no keys stored) |
| Data path | External API endpoints | **Within GCP project** |
| Default model | Provider-specific | **Claude Opus 4.6 on Vertex** |

**Files changed:** Removed `providers/openai/`, `providers/anthropic/`, `providers/nv_build/`. Added `providers/vertex/` with `VertexProvider` class and model registry. Rewrote `llm_utils.py` to use `ChatAnthropicVertex` from `langchain-google-vertexai`.

### Quick Start (Vertex)

**Prerequisites:** Python 3.12+, a GCP project with the Claude model enabled on Vertex AI, and `gcloud` CLI installed.

```bash
# 1. Clone this fork
git clone https://github.com/RH-tj/SkillSpector.git
cd SkillSpector

# 2. Create venv and install
uv venv .venv && source .venv/bin/activate
make install

# 3. Authenticate with Google Cloud
gcloud auth application-default login

# 4. Set your GCP project ID
export ANTHROPIC_VERTEX_PROJECT_ID=your-gcp-project-id

# 5. Scan a skill directory
skillspector scan ./path/to/skills/

# Optional: override region (defaults to "global")
export CLOUD_ML_REGION=us-east5

# Optional: override model
export SKILLSPECTOR_MODEL=claude-sonnet-4-6

# Static-only scan (no LLM, no GCP needed)
skillspector scan ./path/to/skills/ --no-llm
```

### Environment Variables (Vertex)

| Variable | Description | Required |
|----------|-------------|----------|
| `ANTHROPIC_VERTEX_PROJECT_ID` | GCP project hosting the Claude model on Vertex AI | **Yes** (for LLM analysis) |
| `CLOUD_ML_REGION` | Vertex AI region (default: `global`) | No |
| `SKILLSPECTOR_MODEL` | Override the default model (default: `claude-opus-4-6`) | No |
| `SKILLSPECTOR_LOG_LEVEL` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `WARNING`) | No |

### Adaptive Rate Limiter

Large repos (hundreds of skill files) can overwhelm Vertex AI's per-model quota when the LLM semantic analyzers fire hundreds of concurrent requests. This fork adds an **adaptive rate limiter** that automatically adjusts concurrency based on scan size.

| Scan Size | Mode | Behavior |
|-----------|------|----------|
| **<= 50 files** | Aggressive | 10 concurrent requests per analyzer — matches upstream speed for single-skill repos |
| **> 50 files** | Throttled | 5 concurrent requests globally across all analyzers, with exponential backoff + jitter on 429 errors |

The limiter uses a process-wide `threading.Semaphore` shared across all LLM-calling analyzer nodes (SSD, SDI, SQP, and meta-analyzer), regardless of how LangGraph schedules them across threads and event loops. In throttled mode, a second-chance retry layer (exponential backoff from 4s to 120s, up to 6 retries with random jitter) sits on top of LangChain's built-in retry to gracefully handle sustained rate limiting.

The mode is determined automatically — no configuration needed. The scan log reports which mode was selected:

```
INFO [skillspector.rate_limiter] Rate limiter: throttled mode (731 files > 50 threshold, concurrency=5)
```

---

## Overview

AI agent skills (used by Claude Code, Codex CLI, Gemini CLI, etc.) execute with implicit trust and minimal vetting. Research shows that **26.1% of skills contain vulnerabilities** and **5.2% show likely malicious intent**.

SkillSpector helps you answer: **"Is this skill safe to install?"**

## Documentation

- **[Development guide](docs/DEVELOPMENT.md)** — Architecture, package layout, and how to extend the analyzer pipeline.

## Features

- **Multi-format input**: Scan Git repos, URLs, zip files, directories, or single files
- **80+ vulnerability patterns** across 20 categories: prompt injection, data exfiltration, privilege escalation, supply chain, excessive agency, output handling, system prompt leakage, memory poisoning, tool misuse, rogue agent, trigger abuse, dangerous code (AST), taint tracking, YARA signatures, MCP least privilege, MCP tool poisoning, agent snooping, SSRF, anti-refusal jailbreaks, and MCP rug-pull
- **Two-stage analysis**: Fast static analysis + optional LLM semantic evaluation
- **Severity-gated floor**: CRITICAL/HIGH findings survive LLM filtering to prevent prompt-injection-induced false negatives
- **Batch failure isolation**: A single LLM API failure only affects its own file batch, not the entire scan
- **Live vulnerability lookups**: SC4 queries [OSV.dev](https://osv.dev) for real-time CVE data with automatic offline fallback
- **Multiple output formats**: Terminal, JSON, Markdown, and SARIF reports
- **Risk scoring**: 0-100 score with severity labels, per-file executable weighting, and diminishing returns per rule
- **Analysis completeness tracking**: JSON reports include `analysis_completeness` with coverage percentage and LLM analysis status

## Quick Start

### Installation

Create and activate a virtual environment first (all `make` targets assume the venv is active). Use **uv** or **pip**; the Makefile uses `uv` if available, otherwise `pip`.

```bash
# Clone this fork
git clone https://github.com/RH-tj/SkillSpector.git
cd SkillSpector

# Create and activate virtual environment
uv venv .venv && source .venv/bin/activate
# or: python3 -m venv .venv && source .venv/bin/activate

# Install for production use
make install

# Or install with development dependencies
make install-dev
```

### Basic Usage

```bash
# Scan a local skill directory
skillspector scan ./my-skill/

# Scan a single SKILL.md file
skillspector scan ./SKILL.md

# Scan a Git repository
skillspector scan https://github.com/user/my-skill

# Scan a zip file
skillspector scan ./my-skill.zip
```

### Output Formats

```bash
# Terminal output (default) - pretty formatted
skillspector scan ./my-skill/

# JSON output - machine readable
skillspector scan ./my-skill/ --format json --output report.json

# Markdown output - for documentation
skillspector scan ./my-skill/ --format markdown --output report.md

# SARIF output - for CI/CD integration and IDE tooling
skillspector scan ./my-skill/ --format sarif --output report.sarif
```

### LLM Analysis

This fork uses **Google Vertex AI** exclusively for LLM semantic analysis.
Authenticate via Google Application Default Credentials (ADC) and set your
GCP project ID. No API keys are stored or transmitted.

```bash
# Authenticate and configure
gcloud auth application-default login
export ANTHROPIC_VERTEX_PROJECT_ID=your-gcp-project-id

# Run a scan with LLM analysis
skillspector scan ./my-skill/

# Override the default model (claude-opus-4-6)
export SKILLSPECTOR_MODEL=claude-sonnet-4-6
skillspector scan ./my-skill/

# Skip LLM analysis (faster, static analysis only, no GCP needed)
skillspector scan ./my-skill/ --no-llm
```

## Vulnerability Patterns

SkillSpector detects **80+ vulnerability patterns** across 20 categories:

### Prompt Injection (5 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| P1 | Instruction Override | HIGH | Commands to ignore safety constraints |
| P2 | Hidden Instructions | HIGH | Malicious directives in comments/invisible text |
| P3 | Exfiltration Commands | HIGH | Instructions to transmit context externally |
| P4 | Behavior Manipulation | MEDIUM | Subtle instructions altering agent decisions |
| P5 | Harmful Content | CRITICAL | Instructions that could cause physical harm |

### Data Exfiltration (5 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| E1 | External Transmission | MEDIUM | Sending data to external URLs |
| E2 | Env Variable Harvesting | HIGH | Collecting API keys and secrets |
| E3 | File System Enumeration | MEDIUM | Scanning directories for sensitive files |
| E4 | Context Leakage | HIGH | Transmitting conversation context externally |
| E5 | Cloud Storage Exfiltration | HIGH | Uploading data to S3, GCS, or Azure Blob storage |

### Privilege Escalation (5 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| PE1 | Excessive Permissions | LOW | Requesting access beyond stated functionality |
| PE2 | Sudo/Root Execution | MEDIUM | Invoking elevated system privileges |
| PE3 | Credential Access | HIGH | Reading SSH keys, tokens, passwords |
| PE4 | Docker Socket Access | HIGH | Accessing the Docker daemon socket for container control |
| PE5 | Privileged Container / Container Escape | HIGH | Running containers with --privileged, host mounts, nsenter, or cgroup escape techniques |

### Supply Chain (6 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| SC1 | Unpinned Dependencies | LOW | No version constraints on packages |
| SC2 | External Script Fetching | HIGH | curl \| bash and remote code execution |
| SC3 | Obfuscated Code | HIGH | Base64/hex encoded execution |
| SC4 | Known Vulnerable Dependencies | HIGH | Dependencies with known CVEs (live OSV.dev lookup) |
| SC5 | Abandoned Dependencies | MEDIUM | Unmaintained packages without security updates |
| SC6 | Typosquatting | HIGH | Package names similar to popular packages |

### Excessive Agency (4 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| EA1 | Unrestricted Tool Access | HIGH | Unfettered tool access without constraints |
| EA2 | Autonomous Decision Making | HIGH | High-impact decisions without human-in-the-loop |
| EA3 | Scope Creep | MEDIUM | Capabilities extending beyond stated purpose |
| EA4 | Unbounded Resource Access | MEDIUM | No rate limits or quotas on resource consumption |

### Output Handling (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| OH1 | Unvalidated Output Injection | HIGH | Model output used without sanitization |
| OH2 | Cross-Context Output | MEDIUM | Output flows across trust boundaries without validation |
| OH3 | Unbounded Output | MEDIUM | No limits on output size or generation rate |

### System Prompt Leakage (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| P6 | Direct Leakage | HIGH | Instructions that expose system prompts or internal rules |
| P7 | Indirect Extraction | MEDIUM | Extraction via rephrasing, translation, or side-channels |
| P8 | Tool-Based Exfiltration | HIGH | System prompts exfiltrated via file writes or network requests |

### Memory Poisoning (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| MP1 | Persistent Context Injection | HIGH | Content designed to persist across interactions |
| MP2 | Context Window Stuffing | MEDIUM | Filler content displacing safety constraints |
| MP3 | Memory Manipulation | HIGH | Tampering with agent memory or stored state |

### Tool Misuse (4 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| TM1 | Tool Parameter Abuse | HIGH | Crafted parameters for unintended behavior (shell=True, --force) |
| TM2 | Chaining Abuse | HIGH | Tool chains that bypass individual safety checks |
| TM3 | Unsafe Defaults | MEDIUM | Overly permissive defaults (disabled TLS, no auth) |
| TM4 | Privileged Kubernetes Workload | HIGH | Deploying privileged containers, hostPath mounts, or hostPID/hostNetwork pods |

### Rogue Agent (2 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| RA1 | Self-Modification | CRITICAL | Modifying own code or configuration at runtime |
| RA2 | Session Persistence | HIGH | Unauthorized persistence via cron jobs or startup scripts |

### Trigger Abuse (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| TR1 | Overly Broad Trigger | MEDIUM | Trigger patterns matching common words |
| TR2 | Shadow Command Trigger | HIGH | Triggers that shadow built-in commands or other skills |
| TR3 | Keyword Baiting Trigger | MEDIUM | Generic triggers designed to maximize activation |

### Behavioral AST (9 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| AST1 | exec() Call | CRITICAL | Direct exec() enabling arbitrary code execution |
| AST2 | eval() Call | HIGH | Direct eval() evaluating arbitrary expressions |
| AST3 | Dynamic Import | HIGH | \_\_import\_\_() loading arbitrary modules at runtime |
| AST4 | subprocess Call | HIGH | External command execution via subprocess |
| AST5 | os.system / exec-family | HIGH | Shell commands via os module |
| AST6 | compile() Call | MEDIUM | Code object creation from strings |
| AST7 | Dynamic getattr() | MEDIUM | Arbitrary attribute access with non-literal names |
| AST8 | Dangerous Execution Chain | CRITICAL | exec/eval combined with dynamic source (network, encoded data) |
| AST9 | Reflective getattr to Exec Sink | HIGH | getattr() with a constant name resolving to an execution sink (e.g. `getattr(os, "system")`) |

### Taint Tracking (5 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| TT1 | Direct Taint Flow | HIGH | Data flows directly from a source to a sink without sanitization |
| TT2 | Variable-Mediated Taint Flow | MEDIUM | Data flows from source to sink through intermediate variables |
| TT3 | Credential Exfiltration Chain | CRITICAL | Credentials (env vars, secrets) flow to network output sinks |
| TT4 | File Read to Network Exfiltration | HIGH | File contents flow to network output sinks |
| TT5 | External Input to Execution Flow | CRITICAL | External input (network, user) flows to code execution sinks |

### YARA Signatures (4 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| YR1 | Malware Match | CRITICAL | YARA rule match for known malware signatures |
| YR2 | Webshell Match | CRITICAL | YARA rule match for webshell patterns |
| YR3 | Cryptominer Match | HIGH | YARA rule match for crypto mining indicators |
| YR4 | Hack Tool / Exploit Match | HIGH | YARA rule match for hack tools or exploit code |

### MCP Least Privilege (4 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| LP1 | Underdeclared Capability | HIGH | Code uses capabilities not listed in declared permissions |
| LP2 | Wildcard Permission | MEDIUM | Permission list contains wildcards (\*, all, full, any) |
| LP3 | Missing Permission Declaration | MEDIUM | No permissions field but code has detectable capabilities |
| LP4 | Overdeclared Permission | LOW | Permission declared but no corresponding code capability found |

### MCP Tool Poisoning (4 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| TP1 | Hidden Instructions | HIGH | Hidden directives in metadata (HTML comments, zero-width chars, base64, data URIs) |
| TP2 | Unicode Deception | HIGH | Homoglyphs, RTL overrides, mixed-script identifiers in tool metadata |
| TP3 | Parameter Description Injection | MEDIUM | Injection patterns in parameter definitions (overrides, system tokens, malicious defaults) |
| TP4 | Description-Behavior Mismatch | MEDIUM | Declared tool description does not match actual code behavior (LLM-powered) |

### Agent Snooping (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| AS1 | Agent Config Directory Access | HIGH | Reading agent configuration directories (.claude/, .codex/, .gemini/) |
| AS2 | MCP Config Access | HIGH | Accessing MCP server configuration files (mcp.json) containing server addresses and credentials |
| AS3 | Skill Enumeration | MEDIUM | Enumerating or reading other installed skills to discover capabilities or exfiltrate instructions |

### Server-Side Request Forgery (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| SSRF1 | Cloud Metadata Access | HIGH | Accessing cloud instance metadata endpoints (169.254.169.254) to steal IAM credentials |
| SSRF2 | Internal Network Request | MEDIUM | Requests to loopback, link-local, or private-range hosts that may reach internal services |
| SSRF3 | Dynamic Request Target | HIGH | Request target host built from dynamic or untrusted values enabling arbitrary SSRF |

### Anti-Refusal (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| AR1 | Refusal Suppression | MEDIUM | Instructions to never refuse or to always comply, suppressing the agent's safety refusals |
| AR2 | Disclaimer Suppression | MEDIUM | Instructions to omit warnings, disclaimers, or ethical commentary |
| AR3 | Safety Policy Nullification | HIGH | Attempts to nullify the agent's safety policies or content restrictions |

### MCP Rug-Pull (3 patterns)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| RP1 | Unpinned MCP Server | MEDIUM | MCP servers or dependencies referenced without version pinning (npx, uvx, pip, docker) |
| RP2 | Permission Pre-staging | LOW | Manifest language suggesting future permission expansion |
| RP3 | Unpinned Skill Version | LOW | Skill version constraints that are absent or too broad, enabling silent updates |

All detected patterns are listed in the tables above.

## Risk Scoring

### Score Calculation

- **CRITICAL issues**: +50 points
- **HIGH issues**: +25 points
- **MEDIUM issues**: +10 points
- **LOW issues**: +5 points
- **Executable scripts**: 1.3x multiplier

### Severity Levels

| Score | Severity | Recommendation |
|-------|----------|----------------|
| 0-20 | LOW | SAFE |
| 21-50 | MEDIUM | CAUTION |
| 51-80 | HIGH | DO NOT INSTALL |
| 81-100 | CRITICAL | DO NOT INSTALL |

## Example Output

### Terminal Output

```
 SkillSpector Security Report  v2.0.0

Skill: suspicious-skill
Source: ./suspicious-skill/
Scanned: 2026-01-29 10:30:00 UTC

        Risk Assessment
 Metric          Value
 Score           78/100
 Severity        HIGH
 Recommendation  DO NOT INSTALL

        Components (3)
 File              Type      Lines  Executable
 SKILL.md          markdown    142  No
 scripts/sync.py   python       87  Yes
 requirements.txt  text          3  No

Issues (2)

  HIGH: Env Variable Harvesting (E2)
    Location: scripts/sync.py:23
    Finding: for key, val in os.environ.items():...
    Confidence: 94%
    Explanation: This code collects environment variables containing
    API keys and secrets, then sends them to an external server.

  HIGH: External Transmission (E1)
    Location: scripts/sync.py:45
    Finding: requests.post("https://api.skill.io/env"...
    Confidence: 89%
    Explanation: Data is being sent to an external server. Combined
    with env harvesting above, this indicates credential exfiltration.
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ANTHROPIC_VERTEX_PROJECT_ID` | GCP project hosting the Claude model on Vertex AI. | **Yes** (for LLM analysis) |
| `CLOUD_ML_REGION` | Vertex AI region (default: `global`). | No |
| `SKILLSPECTOR_MODEL` | Override the default model (default: `claude-opus-4-6`). Available: `claude-opus-4-6`, `claude-sonnet-4-6`, `claude-opus-4-5`. | No |
| `SKILLSPECTOR_MODEL_REGISTRY` | Override the bundled YAML registry (`src/skillspector/providers/vertex/model_registry.yaml`) with a custom path. | No |
| `SKILLSPECTOR_LOG_LEVEL` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `WARNING`). | No |

**Note:** LLM concurrency is managed automatically by the [adaptive rate limiter](#adaptive-rate-limiter) based on file count (aggressive for <= 50 files, throttled for larger repos).

### CLI Options

```bash
skillspector scan --help

Options:
  -f, --format [terminal|json|markdown|sarif]  Output format [default: terminal]
  -o, --output PATH                            Output file path
  --no-llm                                     Skip LLM analysis (static only)
  -V, --verbose                                Show detailed progress
  --help                                       Show this message and exit
```

## Development

### Setup

All `make` targets assume a virtual environment is already created and activated. The Makefile uses **uv** if available, else **pip**.

```bash
# Clone, create venv, activate, install dev dependencies
git clone https://github.com/RH-tj/SkillSpector.git
cd SkillSpector
uv venv .venv && source .venv/bin/activate
# or: python3 -m venv .venv && source .venv/bin/activate
make install-dev

# Run tests
make test

# Run tests with coverage
make test-cov

# Run linting
make lint

# Format code
make format
```

## How It Works

SkillSpector uses a two-stage detection pipeline:

### Stage 1: Static Analysis
- Fast regex-based pattern matching across 15+ static analyzers
- AST-based behavioral analysis detecting dangerous calls (exec, eval, subprocess, getattr-to-exec, etc.)
- Taint tracking for data-flow analysis (credential exfiltration chains, input-to-exec flows)
- Live vulnerability lookups via OSV.dev for known CVEs in dependencies
- YARA signature matching for known malware, webshells, cryptominers, and exploit code
- MCP manifest analysis for least-privilege violations, tool poisoning, and rug-pull risks
- Scans all files in the skill (binary and PDF files are automatically skipped)
- High recall (catches most issues)
- Moderate precision (some false positives)

### Stage 2: LLM Semantic Analysis (Optional)
- Evaluates context and intent using Vertex AI (Claude on GCP)
- Filters false positives with confidence scoring
- Provides human-readable explanations
- **Severity-gated floor**: CRITICAL and HIGH findings survive LLM filtering — if the LLM does not confirm them, they are retained with an `llm-unconfirmed` tag rather than dropped. This prevents prompt injection in scanned skills from hiding real high-severity findings.
- **Batch failure isolation**: LLM analysis is partitioned by file. If a single batch fails (e.g. due to a Vertex 429 rate limit), only that batch's findings fall back to static-only results — the rest of the scan retains full LLM enrichment.
- **Confidence normalization**: LLM confidence values are automatically normalized (0-100 scale → 0.0-1.0) and clamped, preventing crashes from out-of-range model responses.
- **LLM degradation tracking**: The report includes `llm_call_log` entries showing which LLM calls succeeded and which fell back, so you can tell exactly when LLM analysis was degraded.
- Improves precision to ~87%

The LLM prompt includes anti-jailbreak protections to prevent malicious skills from manipulating the analysis.

## Live Vulnerability Lookups (SC4)

SC4 uses the [OSV.dev](https://osv.dev) API to check dependencies against the full Open Source Vulnerabilities database — covering tens of thousands of advisories across PyPI and npm.

- **No API key required** — OSV.dev is free and unauthenticated.
- **Batch queries** — all dependencies are checked in a single HTTP call.
- **Automatic fallback** — if OSV.dev is unreachable (air-gapped/offline), a small built-in fallback list is used.
- **Caching** — results are cached in-memory for 1 hour to avoid redundant API calls during a session.

The tool requires outbound HTTPS access to `api.osv.dev` for live vulnerability data. When that is not available, findings are limited to the static fallback list.

## Limitations

- **Non-English content**: May miss patterns in other languages
- **Image-based attacks**: Cannot analyze text in images
- **Encrypted/binary code**: Cannot analyze compiled or encrypted content
- **Runtime behavior**: Static analysis only, no dynamic execution
- **Offline SC4**: Without network access to `api.osv.dev`, SC4 uses a small static fallback list

## Research Background

Based on research from "Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale" (Liu et al., 2026):

- **Dataset**: 42,447 skills from major marketplaces
- **Vulnerable**: 26.1% contain at least one vulnerability
- **High-severity**: 5.2% show likely malicious intent
- **Key finding**: Skills with executable scripts are 2.12x more likely to be vulnerable

## Python API Integration

```python
from skillspector import graph

# Invoke the LangGraph workflow
result = graph.invoke({
    "input_path": "/path/to/skill",
    "output_format": "json",   # terminal, json, markdown, or sarif
    "use_llm": True,           # False for static-only analysis
})

# Access results
print(f"Risk Score: {result['risk_score']}/100")
print(f"Severity: {result['risk_severity']}")
print(f"Recommendation: {result['risk_recommendation']}")

for finding in result["filtered_findings"]:
    print(f"[{finding['severity']}] {finding['rule_id']}: {finding['message']}")
```

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## Development Guide — Syncing with Upstream

This fork carries significant modifications to support **Vertex AI exclusively**, including an adaptive rate limiter, JSON response parsing, and hardened meta-analyzer logic. When pulling new changes from [NVIDIA/SkillSpector](https://github.com/NVIDIA/skillspector), certain files **must not be rebased or overwritten** because they contain the core of the fork's value.

### Protected Files (Do Not Rebase/Overwrite)

These files have been substantially rewritten or are unique to this fork. Upstream changes to these files must be **manually ported** — never blindly cherry-picked or rebased.

| File | Why It's Protected |
|------|--------------------|
| `src/skillspector/providers/vertex/` | **Vertex AI provider** — the fork's exclusive LLM backend. Upstream has no equivalent. |
| `src/skillspector/providers/__init__.py` | Rewired to load only the Vertex provider; upstream registers OpenAI/Anthropic/NVIDIA. |
| `src/skillspector/providers/base.py` | Modified base class to support Vertex-specific auth and model registry. |
| `src/skillspector/llm_utils.py` | Rewritten to use `ChatAnthropicVertex` from `langchain-google-vertexai`. Upstream uses multi-provider dispatch. |
| `src/skillspector/llm_analyzer_base.py` | Modified to integrate with the adaptive rate limiter. |
| `src/skillspector/rate_limiter.py` | **Fork-only file.** Process-wide adaptive semaphore with exponential backoff for Vertex AI quota management. |
| `src/skillspector/nodes/meta_analyzer.py` | Heavily modified: JSON parsing for raw Vertex responses, severity-gated floor, batch failure isolation, end_line matching fix, LLM degradation surfacing, confidence normalization. Must be manually ported. |
| `src/skillspector/state.py` | Extended with `llm_call_log` and `llm_call_record()` for LLM degradation tracking. |
| `src/skillspector/cli.py` | Modified for Vertex-specific CLI options and defaults. |
| `pyproject.toml` | Dependencies changed (`langchain-google-vertexai` replaces upstream provider packages). |
| `uv.lock` | Reflects the fork's dependency tree; regenerated from `pyproject.toml`. |
| `README.md` | Completely rewritten for the Vertex fork. |

### Safe to Cherry-Pick From Upstream

These file categories are generally safe to integrate directly:

- **New analyzer modules** (`src/skillspector/nodes/analyzers/`) — new pattern detectors are additive and don't conflict with the fork's changes.
- **Test files** (`tests/`) — new tests for new analyzers typically apply cleanly. Existing test files that import from `providers/` or `llm_utils` may need adaptation.
- **YARA rules** (`src/skillspector/yara_rules/`) — signature updates are independent.
- **Documentation** (`docs/`) — architecture and development docs.
- **CI/Docker files** (`.github/`, `Dockerfile`) — infrastructure that doesn't touch the provider layer.
- **Scoring and report modules** (`src/skillspector/nodes/report.py`, `src/skillspector/nodes/scoring.py`) — upstream improvements to scoring logic are usually compatible.

### Recommended Workflow for Upstream Sync

```bash
# 1. Add upstream remote (one-time)
git remote add upstream https://github.com/NVIDIA/skillspector.git

# 2. Fetch latest upstream
git fetch upstream

# 3. Identify new commits since last sync
git log --oneline upstream/main --not main

# 4. Classify each commit's changed files
#    - If NO overlap with protected files → cherry-pick directly
#    - If ONLY README.md overlap → cherry-pick --no-commit, revert README, commit
#    - If overlap with protected files → manually port the relevant changes

# 5. Cherry-pick safe commits (chronological order)
git cherry-pick <hash>

# 6. For README-conflict commits
git cherry-pick --no-commit <hash>
git checkout HEAD -- README.md
git commit -m "upstream: <original message> (README kept)"

# 7. For protected-file conflicts, manually read the upstream diff and
#    apply the relevant logic into the fork's version of the file.

# 8. Run tests
make test
skillspector scan ./test-skill/ --no-llm  # smoke test
```

### Key Architectural Decisions

1. **Single provider**: All multi-provider dispatch logic has been replaced with direct Vertex AI calls. Upstream commits that add new providers (OpenAI, Bedrock, Anthropic direct) should be **skipped entirely**.

2. **Rate limiting at the process level**: The fork uses a process-wide `threading.Semaphore` shared across all LLM-calling nodes. Upstream has no equivalent — any upstream changes to concurrency or batching in `llm_analyzer_base.py` or `meta_analyzer.py` must be evaluated for compatibility with the semaphore.

3. **JSON response parsing**: The fork's `meta_analyzer.py` includes extensive JSON extraction logic to handle raw Vertex AI responses that may not be cleanly structured. Upstream assumes well-formed responses from their provider layer.

4. **Confidence normalization**: The fork normalizes LLM confidence values from 0-100 scale to 0.0-1.0 via a Pydantic field validator. This was ported from upstream but interacts with the fork's JSON parsing — any upstream changes to the `MetaAnalyzerFinding` model must be checked against this validator.

## Support

- **Fork issues**: [GitHub Issues](https://github.com/RH-tj/SkillSpector/issues)
- **Upstream issues**: [NVIDIA/SkillSpector Issues](https://github.com/NVIDIA/skillspector/issues)
