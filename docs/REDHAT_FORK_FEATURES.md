# Red Hat Fork Features

> Features and enhancements added to the Red Hat fork of [NVIDIA/SkillSpector](https://github.com/NVIDIA/skillspector) beyond the upstream project.

---

## Overview

This fork extends NVIDIA's SkillSpector with detection capabilities targeting emerging attack vectors in agentic AI systems, native support for additional skill file formats, and deployment infrastructure for CI/CD integration.

| Feature | Status | Upstream |
|---------|--------|----------|
| Role Confusion detection (RC-001 – RC-006) | Proposed | Not available |
| CoT Forgery detection (CF-001 – CF-006) | Proposed | Not available |
| Cursor SKILL.md parser | Proposed | Not available |
| Vertex AI exclusive provider | Implemented | Uses OpenAI/Anthropic/NVIDIA |
| Adaptive rate limiter | Implemented | Not available |
| `--min-severity` analysis gate | Implemented | Not available |
| GitHub Action for CI/CD | Planned | Not available |
| Container image (quay.io) | Planned | Not available |

---

## New Detection Categories

### Role Confusion (RC-001 – RC-006)

Detects attempts to hijack agent behavior by exploiting how LLMs assign authority based on writing style. Motivated by the ICML 2026 paper ["Prompt Injection as Role Confusion"](https://arxiv.org/abs/2603.12277) which demonstrates 60% attack success via stylistic role spoofing.

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| RC-001 | Role-Tag Spoofing | `<system>`, `[INST]`, `<<SYS>>`, `<\|im_start\|>` and similar role delimiters in skill content |
| RC-002 | Authority Escalation | "ignore previous instructions", "you are now", "system mode activated" patterns |
| RC-003 | Hierarchy Manipulation | Attempts to redefine trust levels or claim developer/system authority |
| RC-004 | Cross-Role Mimicry | Embedded fake user/assistant dialogue designed to manipulate conversation perception |
| RC-005 | Model-Specific Markers | Formatting tokens specific to Claude, GPT, Llama, Gemini model families |
| RC-006 | Privilege Boundary Crossing | Instructions attempting to modify system prompts or disable safety mechanisms |

**Severity:** HIGH  
**OWASP LLM Top 10 2025:** LLM01 (Prompt Injection)  
**MITRE ATLAS:** AML.T0051 (LLM Prompt Injection)

### CoT Forgery (CF-001 – CF-006)

Detects injected fabricated chain-of-thought reasoning traces that models mistake for their own internal thought processes. The Skill-Inject benchmark demonstrates up to 80% attack success through this vector.

| Rule ID | Name | What It Detects |
|---------|------|-----------------|
| CF-001 | Fabricated Reasoning Traces | Multi-step reasoning patterns ("Step 1:", "Let me think...") in non-reasoning contexts |
| CF-002 | CoT Syntax Spoofing | `<thinking>`, `<scratchpad>`, `<internal_monologue>` blocks in skill content |
| CF-003 | Conclusion Injection | Fabricated reasoning leading to specific conclusions ("Therefore, I should...") |
| CF-004 | Reasoning-Style Mimicry | Dense hedging language, self-correction, and policy-analysis vocabulary |
| CF-005 | Trust Escalation via Reasoning | Fake reasoning justifying privilege escalation or safety bypasses |
| CF-006 | Meta-Reasoning Manipulation | Content referencing the model's own decision-making ("The policy allows...") |

**Severity:** HIGH  
**OWASP LLM Top 10 2025:** LLM01 (Prompt Injection)  
**MITRE ATLAS:** AML.T0051, AML.T0054 (LLM Jailbreak)

---

## Cursor SKILL.md Format Support

Native parsing of Cursor-style SKILL.md files with structural awareness:

- Extracts title, description/instructions, examples, and metadata sections
- Maps to SkillSpector's internal `SkillManifest` model
- Provides section-level context to analyzers for false positive reduction (example sections are analyzed at reduced sensitivity)
- Handles optional YAML frontmatter

```bash
# Scan a directory containing Cursor SKILL.md files
skillspector scan ./path/to/cursor/skills/

# Scan a specific SKILL.md file
skillspector scan ./my-skill/SKILL.md
```

---

## GitHub Action for CI/CD

A GitHub Action that runs SkillSpector as part of pull request checks. Scans skill files changed in the PR and posts findings as PR annotations.

### Usage

```yaml
# .github/workflows/skill-security.yml
name: Skill Security Scan

on:
  pull_request:
    paths:
      - '**/*.md'
      - '**/skills/**'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run SkillSpector
        uses: RH-tj/skillspector-action@v1
        with:
          path: ./skills/
          format: sarif
          no-llm: true  # Static-only for CI speed

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillspector-results.sarif
```

### Features

- **Static-only mode** (`no-llm: true`) — no API keys needed, sub-second per file
- **SARIF output** — integrates with GitHub Code Scanning alerts
- **Path filtering** — only scan files matching specified patterns
- **Severity threshold** — fail the check only for findings at or above a configurable severity

---

## Container Image

Pre-built container image available on quay.io for environments where installing from source is impractical.

```bash
# Pull the image
podman pull quay.io/app-sre/skillspector:latest

# Static-only scan (no GCP/Vertex needed)
podman run --rm -v ./skills:/skills:ro \
  quay.io/app-sre/skillspector:latest \
  scan /skills/ --no-llm --format sarif

# With Vertex AI (mount ADC credentials)
podman run --rm \
  -v ./skills:/skills:ro \
  -v ~/.config/gcloud:/root/.config/gcloud:ro \
  -e ANTHROPIC_VERTEX_PROJECT_ID=my-project \
  quay.io/app-sre/skillspector:latest \
  scan /skills/
```

---

## CLI Examples

### Basic Scanning

```bash
# Scan a directory of skill files (static + LLM)
skillspector scan ./skills/

# Static-only scan (no LLM, no API keys needed)
skillspector scan ./skills/ --no-llm

# Output as SARIF for tool integration
skillspector scan ./skills/ --format sarif --output results.sarif

# Scan with baseline suppression
skillspector scan ./skills/ --baseline baseline.sarif
```

### Targeting New Detection Categories

```bash
# Verbose output showing all rule matches including RC/CF rules
skillspector scan ./skills/ --no-llm --verbose

# Scan a single Cursor SKILL.md file
skillspector scan ./cursor-skills/my-automation/SKILL.md --no-llm
```

### CI Integration

```bash
# Full static+LLM scan, but only analyze/report HIGH and CRITICAL
skillspector scan ./skills/ --min-severity HIGH --format sarif --output results.sarif

# Static-only with the same severity gate (no Vertex tokens)
skillspector scan ./skills/ --no-llm --min-severity HIGH --format json
```

---

## `--min-severity` Analysis Gate

Runtime flag that **skips below-threshold analysis work**, not just report filtering. Primary goal: reduce Vertex AI token spend when operators only care about HIGH/CRITICAL findings.

```bash
skillspector scan ./my-skill/ --min-severity HIGH
skillspector scan ./my-skill/ --min-severity CRITICAL --format json
```

| Threshold behavior | Effect |
|--------------------|--------|
| Static analyzers | Findings below the threshold are dropped before they enter graph state |
| `semantic_quality_policy` | Skipped entirely at HIGH+ (no LLM calls) |
| Discovery LLMs (security / developer intent) | Prompt constrains the model to only emit at/above threshold; lower results discarded |
| Meta-analyzer | Only enriches findings that meet the threshold; files with only below-threshold findings get **no LLM call** (largest token saving) |
| Risk score / exit code | Reflect the gated finding set |

Default is `LOW` (full analysis — same as upstream behavior).

**Tracking:** [APPSRE-15069](https://redhat.atlassian.net/browse/APPSRE-15069)  
**Key files:** `src/skillspector/severity_utils.py`, `cli.py`, `nodes/meta_analyzer.py`, `llm_analyzer_base.py`, `nodes/analyzers/static_runner.py`, `inspection_ledger.py` (`guard_analyzer_node`)

---

## Vertex AI Exclusive Provider

All LLM analysis traffic stays within your GCP project boundary. No external API keys or endpoints are used.

| Aspect | Upstream (NVIDIA) | This Fork |
|--------|-------------------|-----------|
| LLM providers | OpenAI, Anthropic, NVIDIA | Vertex AI only |
| Authentication | API keys via env vars | Google ADC (no keys stored) |
| Data path | External API endpoints | Within GCP project |
| Default model | Provider-specific | Claude Opus 4.6 on Vertex |

See the main [README.md](../README.md) for setup instructions.

---

## References

- Ye, Cui, Hadfield-Menell. "Prompt Injection as Role Confusion." ICML 2026. [arxiv.org/abs/2603.12277](https://arxiv.org/abs/2603.12277)
- Skill-Inject Benchmark (2026). Skill-file prompt injection attack evaluation.
- OWASP. "LLM Top 10 2025." [owasp.org/www-project-top-10-for-large-language-model-applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- MITRE. "ATLAS — Adversarial Threat Landscape for AI Systems." [atlas.mitre.org](https://atlas.mitre.org/)
- [Design Document: Role Confusion and CoT Forgery Detection](design-role-confusion-cot-forgery.md)
- [ADR-001: Add Role Confusion and CoT Forgery Detection](adr/001-role-confusion-cot-forgery-detection.md)
