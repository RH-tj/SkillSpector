# Project Plan: Role Confusion and CoT Forgery Detection

**Status**: Proposed  
**Epic**: APPSRE (see Jira for assigned ticket numbers)  
**Last Updated**: 2026-07-09

## Executive Summary

Enhance the Red Hat fork of NVIDIA SkillSpector with detection capabilities for role confusion and Chain-of-Thought (CoT) forgery attacks, integrate it into automata CI/CD as a GitHub Action, and package it as a container image for broader Red Hat deployment.

## Impact and Value Assessment

### Why This Matters Now

| Research | Finding | Implication |
|---|---|---|
| ICML 2026 "Prompt Injection as Role Confusion" (Ye, Cui, Hadfield-Menell) | CoT Forgery achieves 60% attack success against frontier models | Models cannot distinguish attacker text from their own thoughts |
| Skill-Inject Benchmark (2025) | Up to 80% attack success through skill-file injection | Includes data exfiltration and ransomware-like behavior |
| NVIDIA SkillSpector Research | 26.1% of skills contain vulnerabilities; 5.2% show malicious intent | Supply chain risk is real and measurable |

### Quantified Target State

| Metric | Current State | Target State |
|---|---|---|
| Attack patterns covered | 68 (upstream NVIDIA) | 80+ (adds 12+ new rules) |
| Skill formats supported | NVIDIA skill.json, generic dirs | + Cursor SKILL.md native parsing |
| CI/CD integration | Manual CLI runs | Automated PR gate in automata |
| Deployment reach | Developer laptops | Container image on quay.io for all Red Hat AI teams |

---

## Ticket Breakdown

### Ticket 1: Research Spike — Map Detection Coverage to Taxonomy

**Type**: Spike | **Points**: 3 | **Dependencies**: None

**Scope**:
- Audit all 68 existing SkillSpector rules against ICML 2026 role confusion framework
- Map which existing rules partially cover role confusion (prompt_injection, hidden_instructions, rogue_agent, anti_refusal, trigger_abuse)
- Identify gaps vs. Ye et al. (2026) and Skill-Inject benchmark
- Review skill-scanner repo for reusable patterns

**Deliverable**: Gap analysis document with coverage matrix, identified gaps, recommended new rules prioritized by exploitability and impact.

**Acceptance Criteria**:
- Each of 68 existing rules mapped to taxonomy
- At least 5 specific gap areas identified with concrete attack examples
- Recommendations prioritized by exploitability and impact

---

### Ticket 2: Static Detection — Role Confusion Patterns

**Type**: Story | **Points**: 5 | **Dependencies**: Ticket 1

**New Rules** (analyzer: `src/skillspector/analyzers/role_confusion.py`):

| ID | Name | Description | Severity |
|---|---|---|---|
| RC-001 | Role-tag spoofing | Detect `<thinking>`, `<assistant>`, `<system>`, `[INST]`, `<<SYS>>`, `<\|im_start\|>` in skill instructions | HIGH |
| RC-002 | Authority escalation phrases | Pattern-match "override previous instructions", "ignore all prior", "you are now", "system mode activated" | HIGH |
| RC-003 | Instruction hierarchy manipulation | Attempts to redefine trust levels or claim developer/system role | HIGH |
| RC-004 | Cross-role mimicry | Content switching between role voices (fake user/assistant dialogue) | MEDIUM |
| RC-005 | Model-specific role markers | Formatting specific to known models (Claude XML, GPT headers, Llama tokens) | MEDIUM |
| RC-006 | Privilege boundary crossing | Instructions referencing or modifying the agent's system prompt | CRITICAL |

**Acceptance Criteria**:
- At least 6 rules implemented and tested
- Zero false positives on existing test corpus
- Each rule has severity, OWASP/MITRE mapping, remediation guidance

---

### Ticket 3: Static Detection — CoT Forgery Patterns

**Type**: Story | **Points**: 5 | **Dependencies**: Ticket 1

**New Rules** (analyzer: `src/skillspector/analyzers/cot_forgery.py`):

| ID | Name | Description | Severity |
|---|---|---|---|
| CF-001 | Fabricated reasoning traces | Multi-step reasoning patterns ("Step 1:", "Let me think...") in non-reasoning contexts | HIGH |
| CF-002 | CoT syntax spoofing | `<thinking>`, `<scratchpad>`, `<internal_monologue>` blocks in skill content | HIGH |
| CF-003 | Conclusion injection | Fabricated reasoning leading to specific actions ("Therefore, I should...") | HIGH |
| CF-004 | Reasoning-style mimicry | Text matching known model reasoning styles (hedging, self-correction, policy analysis) | MEDIUM |
| CF-005 | Trust escalation via reasoning | Fake reasoning justifying privilege escalation or safety bypass | CRITICAL |
| CF-006 | Meta-reasoning manipulation | Content referencing model's decision-making ("The policy allows...", "My guidelines state...") | HIGH |

**Acceptance Criteria**:
- At least 6 rules implemented
- False positive rate < 5% on benign skill corpus
- Each rule has severity, OWASP/MITRE mapping, remediation guidance
- YARA rules for CoT-style content patterns included

---

### Ticket 4: Semantic (LLM) Analysis — Role Confusion and CoT Forgery

**Type**: Story | **Points**: 8 | **Dependencies**: Tickets 2, 3

**New Semantic Checks** (extends `src/skillspector/semantic/`):

1. **Role Impersonation Check**: LLM evaluates whether skill content attempts to impersonate a system/developer/assistant role through stylistic mimicry
2. **CoT Spoofing Analysis**: LLM identifies fabricated reasoning traces that could be mistaken for internal thought processes
3. **Destyling Test**: Remove reasoning vocabulary and compare — if meaning changes significantly, content relies on style for its effect (attack indicator)

**Implementation Notes**:
- Follow patterns in `docs/LLM_ANALYZER_BASE_GUIDE.md`
- Runs only when `--no-llm` is NOT set
- Works with OpenAI and Anthropic providers
- Integrates with existing confidence scoring

**Acceptance Criteria**:
- Three semantic checks implemented
- Detection rate >= 70% on crafted test corpus
- False positive rate < 10% on benign skills
- Works with at least 2 LLM providers

---

### Ticket 5: Cursor SKILL.md Format Parser

**Type**: Story | **Points**: 5 | **Dependencies**: None (parallel-safe)

**Implementation** (`src/skillspector/parsers/cursor_skill.py`):
- Parse Cursor-style SKILL.md markdown files
- Extract: title (H1), description (prose), instructions, examples, metadata, frontmatter
- Map to SkillSpector's internal `SkillManifest` model
- Auto-detect format when scanning directories (look for SKILL.md files)

**Acceptance Criteria**:
- Parses all SKILL.md files from automata/skills/ without errors
- All 68 existing rules + new rules work on parsed Cursor skills
- CLI auto-detects format (no special flag needed)
- Unit tests with sample SKILL.md files (benign + malicious)

---

### Ticket 6: GitHub Action — automata CI/CD Integration

**Type**: Task | **Points**: 5 | **Dependencies**: Tickets 5, 8

**Requirements**:
- Trigger on PR creation/update when `skills/` directory is changed
- Only scan new/modified skill files (diff-aware)
- Static analysis only by default (`--no-llm`); semantic opt-in via PR label
- SARIF output uploaded to GitHub Code Scanning
- Configurable pass/fail threshold (default: block on HIGH/CRITICAL)
- Target < 60 seconds for single-skill scan

**Implementation**:
- Reusable action: `.github/actions/skillspector-scan/action.yml`
- Workflow: `.github/workflows/skillspector-scan.yml`
- Uses SkillSpector container image from quay.io
- `git diff` to identify changed skill files
- SARIF upload via `github/codeql-action/upload-sarif`

**Acceptance Criteria**:
- Triggers only on PRs touching skills/
- Only scans changed/new files
- SARIF annotations appear inline in PR
- PR blocked on HIGH/CRITICAL (configurable)
- Runs in < 60 seconds
- Reusable by other repos (parameterized)

---

### Ticket 7: Container Image — quay.io Build and Publish

**Type**: Task | **Points**: 3 | **Dependencies**: None (parallel-safe)

**Requirements**:
- Base image: Python 3.12 slim or UBI 9 minimal
- Contains SkillSpector CLI + all deps + YARA rules
- Entry point: `skillspector scan`
- Size target: < 500MB
- Registry: quay.io/app-sre/skillspector
- Tags: semver + `latest` + git SHA

**Implementation**:
- `Dockerfile` in repo root
- Multi-stage build
- Makefile targets: `make container-build`, `make container-push`
- CI pipeline for build/push on tag

**Acceptance Criteria**:
- Builds successfully
- Runs `skillspector scan` on mounted directories
- Image < 500MB
- CI builds and tags on release
- Works as base for GitHub Action

---

### Ticket 8: Documentation — ADR, Design Doc, README

**Type**: Task | **Points**: 3 | **Dependencies**: None (parallel-safe)

**Deliverables**:
1. `docs/adr/001-role-confusion-cot-forgery-detection.md` — ADR for architecture decisions
2. `docs/design-role-confusion-cot-forgery.md` — Technical design with threat model and rule specs
3. `docs/REDHAT_FORK_FEATURES.md` — What the Red Hat fork adds beyond upstream

**Acceptance Criteria**:
- ADR follows standard format
- Design doc includes threat model, all rule specs, integration points
- Features README has usage examples and research references
- All docs reference ICML 2026 paper and Skill-Inject benchmark

---

## Dependency Graph

```
Ticket 1 (Research Spike)
├── Ticket 2 (Static: Role Confusion) ──┐
├── Ticket 3 (Static: CoT Forgery) ─────┼── Ticket 4 (Semantic LLM Analysis)
│                                        │
Ticket 5 (Cursor Parser) ───────────────┼── Ticket 6 (GitHub Action)
│                                        │
Ticket 7 (Container Image) ─────────────┘
│
Ticket 8 (Documentation) ── [No dependencies, parallel]
```

## Suggested Sprint Allocation

| Sprint | Tickets | Rationale |
|---|---|---|
| Sprint 1 | 1, 5, 7, 8 | Research + parallel-safe infra work |
| Sprint 2 | 2, 3 | Static rules informed by research spike |
| Sprint 3 | 4, 6 | Semantic analysis + CI integration (depends on rules + parser + container) |

## Risk Register

| Risk | Impact | Mitigation |
|---|---|---|
| False positives on legitimate reasoning-style documentation | Medium — annoys developers, erodes trust | Baseline/suppression mechanism; tune thresholds on real skill corpus |
| CoT forgery patterns evolve faster than rules | Medium — new attack variants bypass detection | Semantic (LLM) layer provides adaptive detection; periodic rule updates |
| LLM API costs for semantic analysis | Low — only used for pre-publish review | Static-only mode for CI; semantic opt-in via label/flag |
| Upstream NVIDIA adds competing features | Low — our fork diverges | Track upstream; contribute back where possible |
| Cursor SKILL.md format changes | Low — format is simple markdown | Parser is resilient to structure variations |

## References

- [Prompt Injection as Role Confusion (ICML 2026)](https://arxiv.org/abs/2603.12277)
- [Skill-Inject: LLM Vulnerability to Skill File Attacks](https://www.emergentmind.com/papers/2602.20156)
- [NVIDIA SkillSpector](https://github.com/nvidia/skillspector)
- [NVIDIA Skill Documentation — Scanning Agent Skills](https://docs.nvidia.com/skills/scanning-agent-skills)
- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/)
