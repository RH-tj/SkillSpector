# SkillSpector — Technical Capabilities Primer

> **Audience:** engineers evaluating or adopting SkillSpector who understand why
> AI-agent skill inspection is necessary but have not used the tool before.
>
> **Scope:** post-refactor state as of 2026-08-12 (fork `RH-tj/SkillSpector`,
> synced to upstream `nvidia/SkillSpector` @ `v2.9.3+6`).

---

## 1. What SkillSpector Is

SkillSpector is a **static + semantic analysis pipeline** for AI-agent skills
(MCP tools, LangChain/LangGraph skills, autonomous agent plugins, prompt files,
etc.). It inspects skill artifacts — source code, prompts, manifests, YARA
signatures — and produces a scored risk report identifying security threats,
supply-chain risks, and policy violations.

It is **not** a general-purpose SAST tool. It targets threat vectors unique to
AI-agent ecosystems: prompt injection, tool poisoning, data exfiltration via
agentic channels, excessive autonomy, and skill supply-chain compromise.

**Navigation:** [CODEBASE_MAP.md](CODEBASE_MAP.md) (files, functions, call graph).
**Why an LLM at all?** [WHY_LLM_ANALYSIS.md](WHY_LLM_ANALYSIS.md) — static is the
baseline; LLM is optional depth/precision (`--no-llm` is a first-class mode).

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                         CLI / MCP entrypoint                         │
└───────────────┬──────────────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────────────────────────────┐
│  resolve_input → build_context                                       │
│  (git clone / zip extract / dir walk → file inventory + metadata)    │
└───────────────┬──────────────────────────────────────────────────────┘
                │
                ▼  (parallel fan-out)
┌──────────────────────────────────────────────────────────────────────┐
│  23 Analyzer Nodes (static patterns, YARA, AST, taint, MCP, LLM)    │
│  Each wrapped in guard_analyzer_node (failure → ledger, not crash)   │
└───────────────┬──────────────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────────────────────────────┐
│  meta_analyzer (LLM) — filter false positives + enrich explanations  │
└───────────────┬──────────────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────────────────────────────┐
│  finalize_inspection_ledger — completeness accounting                │
└───────────────┬──────────────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────────────────────────────┐
│  report — risk scoring, dedup, sanitization, format output           │
│  (terminal / json / markdown / SARIF)                                │
└──────────────────────────────────────────────────────────────────────┘
```

The pipeline is a **LangGraph** state machine. Analyzer nodes run concurrently;
the rest runs sequentially. LLM nodes (semantic analyzers + meta-analyzer) are
optional — `--no-llm` degrades gracefully to static-only analysis.

---

## 3. Input Handling

| Source type | Mechanism |
|-------------|-----------|
| Git URL | Shallow clone; host allowlist (`github.com`, `gitlab.com`, `bitbucket.org`) |
| Raw file URL | `httpx` fetch; bounded by `INGEST_MAX_BYTES` |
| Local zip / archive | Zip extraction; guarded against zip-slip + zip-bomb (`INGEST_MAX_ZIP_MEMBERS`) |
| Single `.md` file | Direct read |
| Local directory | Walk |
| MCP Registry JSON | `--mcp-registry` flag; parsed as tool manifest |

**SSRF protection:** private-IP check + DNS resolution guard prevents fetching
from internal networks / cloud metadata endpoints.

**Multi-skill mode:** if the target directory has no root `SKILL.md` but ≥2
immediate child dirs each containing `SKILL.md`, each child is scanned
independently (`--recursive`).

---

## 4. Analysis Layers

### 4.1 Static Pattern Matching (14 analyzers)

Regex-based rule engines scanning file content against curated patterns. Each
analyzer focuses on one threat category. Patterns are tuned for AI-agent-specific
idioms rather than generic code smells.

| Analyzer | Rule IDs | Threat Category |
|----------|----------|-----------------|
| Prompt Injection | P1–P4, P9 | Override instructions, hidden/invisible instructions, external transmission, subtle steering, whitespace padding |
| Data Exfiltration | E1–E5 | External URL transmission, env harvesting, FS enumeration, conversation-context leak, cloud-storage upload |
| Privilege Escalation | PE1–PE5 | Excessive permissions, sudo/root access, credential-file reads, Docker socket, privileged containers |
| Supply Chain | SC1–SC8, TR1–TR3 | Unpinned deps, remote code execution, obfuscation, known CVEs (OSV lookup), abandoned packages, typosquatting, untrusted images, shipped bytecode; trigger abuse patterns |
| Harmful Content | P5 | Physical-harm instructions |
| Excessive Agency | EA1–EA4 | Unrestricted tools, autonomous high-impact decisions, scope creep, unbounded resources |
| Output Handling | OH1–OH3 | Unvalidated output injection, cross-context output, unbounded output |
| System Prompt Leakage | P6–P8 | Direct/indirect system-prompt exposure, exfil via tool channels |
| Memory Poisoning | MP1–MP3 | Persistent injection, context stuffing, memory manipulation |
| Tool Misuse | TM1–TM4 | Parameter abuse, chaining abuse, unsafe defaults, privileged K8s workloads |
| Rogue Agent | RA1–RA2 | Self-modification, session persistence |
| Agent Snooping | AS1–AS3 | Agent config directory access, MCP config reads, other-skill enumeration |
| Anti-Refusal | AR1–AR3 | Refusal/disclaimer/safety-policy nullification jailbreaks |
| SSRF | SSRF1–SSRF3 | Cloud metadata access, private/loopback requests, dynamic request targets |

### 4.2 YARA Engine (1 analyzer)

Binary/text pattern matching using compiled YARA rules. Detects known-bad
artifacts that may be embedded in or alongside skill code.

| Rule file | Rule ID | Detects |
|-----------|---------|---------|
| `malware.yar` | YR1 | Reverse shells, backdoor persistence, keyloggers, ransomware, C2 frameworks, info stealers |
| `webshells.yar` | YR2 | PHP/Python/JSP/ASPX webshells (generic + known families) |
| `cryptominers.yar` | YR3 | Stratum protocol, mining pools, browser cryptojacking |
| `hacktools.yar` | YR4 | Offensive tools, network recon, priv-esc tools, exploit frameworks, phishing kits |
| `agent_skills.yar` | YR1/YR4 | Agent-skill specific: credential→webhook exfil, remote bootstrap, prompt-injection hidden instructions, MCP poisoning, destructive autonomous actions |

User-supplied YARA rules are loaded via `--yara-rules-dir`.

### 4.3 Behavioral Analysis (2 analyzers, static)

AST-level analysis of Python source code — no LLM, no pattern-matching on
strings.

| Analyzer | Rule IDs | Technique |
|----------|----------|-----------|
| Behavioral AST | AST1–AST9 | Flags dangerous Python execution constructs: `exec`, `eval`, `__import__`, `subprocess`, `os.system`, `compile`, dynamic `getattr`, dangerous call chains, reflective sinks |
| Taint Tracking | TT1–TT5 | Source→sink data-flow analysis: direct flows, variable-mediated flows, credential flows, file-content flows, external-input→execution flows |

### 4.4 MCP Analyzers (3 analyzers)

Specialized for the **Model Context Protocol** tool ecosystem.

| Analyzer | Rule IDs | Technique |
|----------|----------|-----------|
| Least Privilege | LP1–LP4 | Compares declared capabilities against actual tool behavior — underdeclared, wildcard, missing, overdeclared |
| Tool Poisoning | TP1–TP4 | Hidden metadata instructions (TP1), Unicode deception (TP2), parameter-description injection (TP3), description–behavior mismatch via **LLM** (TP4) |
| Rug Pull | RP1–RP3 | Unpinned MCP/server references, permission pre-staging language, unpinned/broad skill version constraints |

### 4.5 Semantic Analyzers (3 analyzers, LLM-powered)

These use an LLM (Vertex AI / Claude in this fork) to perform deep semantic
analysis that regex patterns cannot achieve. Skipped when `--no-llm` is passed.
See [WHY_LLM_ANALYSIS.md](WHY_LLM_ANALYSIS.md) for the rationale, limits, and how
LLM output is (and is not) evaluated in tests.

| Analyzer | Rule IDs | What the LLM evaluates |
|----------|----------|------------------------|
| Security Discovery | SSD-1 – SSD-4 | Semantic prompt injection (paraphrased/novel attacks not matching static patterns), NL-encoded exfiltration, gradual narrative deception |
| Developer Intent | SDI-1 – SDI-4 | Description–behavior mismatch, context-inappropriate capability, scope creep vs declared permissions, intent–code divergence |
| Quality Policy | SQP-1 – SQP-3 | Vague or missing triggers, absent user warnings, natural-language policy violations |

### 4.6 Meta-Analyzer (LLM filter/enrichment layer)

After all 23 analyzers produce findings, the meta-analyzer performs a second LLM
pass that:

1. **Filters** false positives — each finding is evaluated for true vulnerability
   status; findings below confidence 0.6 are dropped.
2. **Enriches** — adds human-readable explanation and remediation for confirmed
   findings.
3. **Fail-closed** — if the LLM is unavailable or errors, all findings pass
   through with default remediations rather than being silently dropped.

---

## 5. Reliability & Completeness Features

### 5.1 Inspection Ledger

Every analyzer node reports what it planned to inspect vs. what it actually
completed. The `finalize_inspection_ledger` node aggregates this into an
`AnalysisCompleteness` record:

- **Coverage %** — files fully inspected vs. total inventory
- **Fully / partially / entirely uninspected** file lists
- **Analyzer-level status** — planned, completed, skipped, failed counts per node
- **Degradation messages** — human-readable limitations (e.g., "LLM unavailable;
  semantic analyzers skipped")
- **Execution success flag** — pipeline ran without fatal ledger exceptions

This means the report explicitly states when analysis is **incomplete**, rather
than silently omitting findings due to errors.

### 5.2 Retry Logic (LLM calls)

- **Structured output retries** — Pydantic validation failures are retried up to
  `STRUCTURED_RESPONSE_MAX_RETRIES` times with exponential backoff.
- **API connection retries** — transient network errors are retried up to
  `API_CONNECTION_MAX_RETRIES` times.
- **Batch failure tracking** — `BatchExecutionResult` records per-batch outcomes
  so partial LLM failures are accounted for in the ledger.

### 5.3 Concurrency Control

LLM calls are gated by an adaptive rate limiter:

- Small scans (few files) → low concurrency to avoid burst-throttling.
- Large scans → higher concurrency for throughput.
- **Environment override:** `SKILLSPECTOR_MAX_LLM_CONCURRENCY` to force a specific
  parallelism level.

### 5.4 Guard Nodes

Each analyzer is wrapped in `guard_analyzer_node`. If an analyzer crashes at
runtime, the guard catches the exception and emits a ledger "failed" event
instead of crashing the entire pipeline. The remaining analyzers and the report
still complete.

---

## 6. Output & Reporting

### 6.1 Risk Scoring

Findings are scored using a **diminishing-returns model**:

| Severity | Base Points |
|----------|-------------|
| CRITICAL | 50 |
| HIGH | 25 |
| MEDIUM | 10 |
| LOW | 5 |

- First occurrence of a rule → full points
- Second occurrence → 50%
- Third occurrence → 25%
- Beyond third → ignored (prevents inflation)
- Contribution scaled by finding confidence (0–1)
- Floor rules: some rule IDs (e.g., `SC8` shipped bytecode) enforce minimum
  scores regardless of confidence

**Bands:**

| Score | Severity | Recommendation |
|-------|----------|----------------|
| 0–20 | LOW | SAFE |
| 21–50 | MEDIUM | CAUTION |
| 51–80 | HIGH | DO_NOT_INSTALL |
| 81–100 | CRITICAL | DO_NOT_INSTALL |

### 6.2 Output Formats

| Format | Use case |
|--------|----------|
| `terminal` | Human-readable Rich-formatted console output |
| `json` | Machine-parseable; suitable for CI/CD gating |
| `markdown` | GitLab/GitHub PR comments, documentation |
| `sarif` | IDE integration, GitHub Code Scanning, OASIS SARIF v2.1.0 compliant |

### 6.3 Deduplication

Before scoring, findings are deduplicated by `(rule_id, file, start_line,
end_line, message)`. Identical matches from multiple analyzers are merged.

### 6.4 Sanitization

Finding text fields (message, explanation, remediation, code_snippet) are
stripped of ANSI escape sequences and control characters. This prevents scanned
malicious content from corrupting the report itself.

---

## 7. Baseline Suppression

For managing known/accepted findings across repeated scans:

```bash
# Generate a baseline
skillspector baseline ./my-skill --output .skillspector-baseline.yaml

# Scan with suppression
skillspector scan ./my-skill --baseline .skillspector-baseline.yaml
```

**Two suppression mechanisms:**

1. **Rules** — human-authored glob patterns on `id`, `path`, and `message`
   (fnmatch semantics). Useful for broad exclusions ("ignore all E1 findings in
   `tests/`").
2. **Fingerprints** — SHA-256 of evidence-bound payload (file hash + scanner
   version + finding fields). Generated automatically; invalidated when file
   content or scanner version changes.

Suppressed findings do not affect the risk score or appear in default SARIF
output. `--show-suppressed` lists them separately for audit.

---

## 8. Threat Vectors Addressed

| Threat Vector | Coverage | Technique Used |
|---------------|----------|----------------|
| **Prompt injection** (direct, indirect, encoded) | Strong | Static patterns (P1–P4, P9) + YARA + Semantic LLM (SSD-1–2) |
| **Data exfiltration** (URL, env, FS, cloud, conversation) | Strong | Static (E1–E5) + Taint tracking (TT1–TT5) + Semantic (SSD-3) |
| **Supply-chain compromise** (deps, CVEs, typosquatting) | Strong | Static (SC1–SC8) + OSV database lookup + YARA |
| **MCP tool poisoning** (hidden instructions, Unicode, param injection) | Strong | MCP analyzers (TP1–TP4) including LLM for semantic mismatch |
| **Excessive autonomy / agency** | Moderate | Static (EA1–EA4) + Developer Intent LLM (SDI-1–4) |
| **Privilege escalation** (host escape, credential access) | Moderate | Static (PE1–PE5) + AST (AST1–9) |
| **System prompt leakage** | Moderate | Static (P6–P8) |
| **Memory/context poisoning** | Moderate | Static (MP1–MP3) |
| **Known malware / offensive tools** | Moderate | YARA (YR1–YR4) |
| **SSRF in skill code** | Moderate | Static (SSRF1–3) + input handler validation |
| **Trigger abuse** (broad/shadow/baiting) | Moderate | Static (TR1–TR3) |
| **Anti-refusal jailbreaks** | Basic | Static (AR1–AR3) |
| **Output handling risks** | Basic | Static (OH1–OH3) |
| **Rogue agent behavior** | Basic | Static (RA1–RA2) |
| **Description–behavior mismatch** | Good (LLM) | Developer Intent (SDI-1–4) + MCP Poisoning (TP4) |

---

## 9. Gaps & Limitations

### 9.1 Not Addressed

| Gap | Why |
|-----|-----|
| **Runtime behavior / dynamic analysis** | SkillSpector is purely static + semantic inference; it does not execute skill code in a sandbox. An attacker hiding behavior behind runtime conditions (time bombs, A/B gating) will not be caught unless patterns appear in source. |
| **Multi-turn attack chains** | Analysis is single-pass over artifacts. It cannot reason about multi-step attack sequences that unfold across conversation turns. |
| **Encrypted / heavily obfuscated payloads** | YARA and pattern matching operate on cleartext. Base64 is partially handled, but custom encryption or steganography defeats static analysis. |
| **Binary artifacts / compiled extensions** | No disassembly or binary analysis. Compiled `.so`/`.dll`/`.wasm` within skills are opaque. |
| **Model weight / adapter poisoning** | Cannot inspect LoRA adapters, GGUF files, or fine-tuned model weights for embedded backdoors. |
| **Network-time behavior** (C2 callbacks, DNS exfil) | Would require runtime monitoring, not static analysis. |
| **Natural language in non-English** | Pattern matching and LLM prompts are English-centric. Attacks encoded in other languages may evade detection. |
| **Image/audio/video-based attacks** | No multimodal analysis of embedded media files. |

### 9.2 Partial / Degraded Coverage

| Area | Limitation |
|------|-----------|
| **Semantic analysis without LLM** | `--no-llm` disables 3 semantic analyzers and the meta-analyzer filter. Coverage drops significantly — only static + YARA + AST remain. No false-positive filtering occurs. |
| **Non-Python taint tracking** | `behavioral_ast` and `behavioral_taint_tracking` only analyze Python ASTs. Skills written in JavaScript, TypeScript, Go, Rust, etc. get pattern-matching only. |
| **Large monorepos** | Designed for single-skill or multi-skill directories. Very large monorepos with hundreds of unrelated modules may produce noisy results and long scan times. |
| **Novel attack patterns** | Static patterns require updates for new attack techniques. The semantic LLM layer partially compensates (it can identify "novel phrasing" of known attack categories) but cannot detect entirely new threat classes. |
| **Confidence calibration** | LLM confidence values are self-reported by the model; they are normalized to [0, 1] but not externally calibrated against ground truth. |
| **Rate-limited environments** | Under heavy API throttling, LLM batches may time out and result in partial coverage (tracked in the inspection ledger). |

### 9.3 Architectural Boundaries

- **No CI/CD integration out of the box** — the tool produces reports and exit
  codes but does not natively integrate with GitHub Actions / GitLab CI as a
  "check." Integration requires wrapping the CLI.
- **No remediation automation** — findings include remediation text but the tool
  does not auto-fix code.
- **No historical trending** — each scan is independent. Tracking risk score
  over time requires external tooling (baseline diffing partially addresses
  this).
- **Single-language AST** — the Python-specific behavioral analyzers do not
  have equivalents for other languages yet.

---

## 10. Summary of Detection Techniques

| Technique | Analyzers Using It | Strengths | Weaknesses |
|-----------|--------------------|-----------|------------|
| Regex pattern matching | 14 static analyzers | Fast, deterministic, no API cost | Evasion via rephrasing, encoding |
| YARA rules | 1 (5 rule files, ~26 rules) | Proven malware detection, community rules | Requires signature updates |
| Python AST traversal | 2 behavioral analyzers | Structural, not fooled by formatting | Python-only |
| Source→sink taint | 1 behavioral analyzer | Finds data flows across variables | Intra-procedural only, Python-only |
| LLM semantic analysis | 3 semantic + meta-analyzer | Catches novel phrasings, understands intent | Costly, latency, non-deterministic |
| OSV database lookup | 1 (SC4 supply chain) | Real CVE data | Requires network; only known vulns |
| MCP manifest inspection | 3 MCP analyzers | Protocol-aware | Limited to MCP-conforming manifests |

---

## 11. CLI Quick Reference

```bash
# Full scan (static + LLM semantic)
skillspector scan ./path/to/skill --format json --output report.json

# Static-only (no LLM, no API cost)
skillspector scan ./path/to/skill --no-llm --format sarif -o report.sarif

# Recursive multi-skill scan
skillspector scan ./agents-monorepo --recursive --format markdown -o report.md

# With baseline suppression
skillspector scan ./skill --baseline .skillspector-baseline.yaml

# Generate baseline from current findings
skillspector baseline ./skill --output .skillspector-baseline.yaml

# MCP Registry scan
skillspector scan --mcp-registry registry.json --format json -o registry-report.json

# Run as MCP server (for IDE integration)
skillspector mcp --transport stdio
```

**Key environment variables:**

| Variable | Purpose |
|----------|---------|
| `SKILLSPECTOR_MODEL` | Override default model for LLM analyzers |
| `SKILLSPECTOR_MAX_LLM_CONCURRENCY` | Force LLM parallelism level |
| `SKILLSPECTOR_LOG_LEVEL` | Set logging verbosity |
| `ANTHROPIC_VERTEX_PROJECT_ID` | GCP project for Vertex AI (this fork) |
| `CLOUD_ML_REGION` | GCP region for Vertex AI (this fork) |

**Exit codes:** `0` = safe, `1` = risk above threshold, `2` = execution error.

---

## 12. Detection Rule Count Summary

| Category | Rule IDs | Count |
|----------|----------|-------|
| Prompt Injection | P1–P9 | 9 |
| Data Exfiltration | E1–E5 | 5 |
| Privilege Escalation | PE1–PE5 | 5 |
| Supply Chain | SC1–SC8 | 8 |
| Trigger Abuse | TR1–TR3 | 3 |
| Excessive Agency | EA1–EA4 | 4 |
| Output Handling | OH1–OH3 | 3 |
| Memory Poisoning | MP1–MP3 | 3 |
| Tool Misuse | TM1–TM4 | 4 |
| Rogue Agent | RA1–RA2 | 2 |
| Agent Snooping | AS1–AS3 | 3 |
| Anti-Refusal | AR1–AR3 | 3 |
| SSRF | SSRF1–SSRF3 | 3 |
| YARA | YR1–YR4 | 4 |
| Behavioral AST | AST1–AST9 | 9 |
| Taint Tracking | TT1–TT5 | 5 |
| MCP Least Privilege | LP1–LP4 | 4 |
| MCP Tool Poisoning | TP1–TP4 | 4 |
| MCP Rug Pull | RP1–RP3 | 3 |
| Semantic Security | SSD-1–SSD-4 | 4 |
| Semantic Intent | SDI-1–SDI-4 | 4 |
| Semantic Quality | SQP-1–SQP-3 | 3 |
| **Total** | | **~95** |
