# ADR-001: Add Role Confusion and CoT Forgery Detection

**Date:** 2026-07-09  
**Status:** Proposed  
**Authors:** App-SRE AI Security Team

---

## Context

### The Attack Landscape

The ICML 2026 paper ["Prompt Injection as Role Confusion"](https://arxiv.org/abs/2603.12277) (Ye, Cui, Hadfield-Menell) demonstrates that LLMs infer roles from writing style rather than structural tags. Text that *sounds* like a system prompt inherits system-level authority regardless of where it appears in the context window. The paper reports a **60% attack success rate** using Chain-of-Thought (CoT) Forgery — injecting fabricated reasoning traces that models mistake for their own internal thought processes.

The Skill-Inject benchmark extends this finding to agent skill files specifically, demonstrating **up to 80% attack success** through skill-file prompt injection that exploits role confusion and CoT spoofing vectors.

### Gap in Current Detection

SkillSpector's existing rule set includes related patterns:

| Existing Pattern | What It Detects | What It Misses |
|-----------------|-----------------|----------------|
| `prompt_injection` | Explicit injection markers | Stylistic mimicry without explicit markers |
| `hidden_instructions` | Concealed directives | Reasoning-style manipulation disguised as documentation |
| `rogue_agent` | Agent autonomy violations | Role-authority spoofing within trusted skill boundaries |

None of these specifically target:
- **Stylistic role spoofing** — content that inherits authority through writing style alone
- **Fabricated reasoning traces** — fake CoT that models adopt as their own thinking
- **Model-specific role markers** — tokens like `<|im_start|>`, `<<SYS>>`, `[INST]` embedded in skill content

### Organizational Context

Red Hat teams are rapidly adopting agentic AI tooling. Skill file formats proliferate (Cursor SKILL.md, MCP tool definitions, custom automation manifests). Each format introduces new surface area for role confusion and CoT forgery attacks. The current scanner cannot parse Cursor SKILL.md files natively.

---

## Decision

### 1. Implement Role Confusion and CoT Forgery Detection

Add two new detection categories with 12 total static rules:

- **Role Confusion (RC-001 through RC-006):** Detect role-tag spoofing, authority escalation phrases, instruction hierarchy manipulation, cross-role mimicry, model-specific role markers, and privilege boundary crossing.
- **CoT Forgery (CF-001 through CF-006):** Detect fabricated reasoning traces, CoT syntax spoofing, conclusion injection, reasoning-style mimicry, trust escalation via reasoning, and meta-reasoning manipulation.

### 2. Dual Analysis Approach

Implement both **static heuristic rules** and **semantic (LLM) analysis** for these categories:

- **Static rules** provide deterministic CI-speed detection (`--no-llm` mode). No API keys required, sub-second execution per file.
- **Semantic analysis** adds depth via the existing LLM analyzer framework. It performs destyling tests, role impersonation checks, and CoT spoofing analysis that cannot be captured by regex alone.

### 3. Native Cursor SKILL.md Support

Add a dedicated parser for the Cursor SKILL.md format rather than relying on wrapper scripts or generic markdown parsing. This ensures structural awareness of the format's sections and metadata.

---

## Consequences

### Positive

- **Closes detection gaps** for attack vectors that upstream NVIDIA SkillSpector does not yet address. Positions the Red Hat fork as a security-hardened superset.
- **CI-friendly** — static rules run without LLM access, enabling integration in GitHub Actions workflows where API keys may not be available or desired.
- **Research-grounded** — detection logic directly maps to peer-reviewed attack taxonomy (ICML 2026) and empirical benchmarks (Skill-Inject).
- **Format coverage** — native Cursor SKILL.md support means Red Hat teams using Cursor get first-class scanning without conversion steps.

### Negative

- **LLM cost and latency** — semantic analysis requires Vertex AI API access. Each skill file incurs one or more LLM calls for deep analysis. Mitigated by making semantic analysis opt-in (`--no-llm` disables it).
- **False positive risk** — CoT forgery detection may flag legitimate reasoning-style documentation in skill files. Skills that document model behavior (e.g., "If the user asks X, respond with Y") or include example prompts for training purposes could trigger rules. Mitigated by the existing baseline/suppression mechanism.
- **Maintenance burden** — attack patterns evolve. New model families introduce new role markers and reasoning formats. Detection rules require ongoing updates as the threat landscape shifts.

### Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Attack evolution outpaces rules | Medium | High | Semantic analysis provides generalized detection; static rules are easily extensible |
| False positives erode trust | Medium | Medium | Suppression baselines; severity tuning; clear documentation of what triggers each rule |
| Upstream divergence | Low | Low | Fork maintains clean separation; new analyzers are additive, not modifications of existing code |

---

## Alternatives Considered

### 1. Wait for Upstream NVIDIA Implementation

**Rejected.** NVIDIA's upstream roadmap does not indicate near-term plans for role confusion or CoT forgery detection. Red Hat's internal adoption timeline requires coverage now.

### 2. Static Rules Only (No Semantic Analysis)

**Rejected.** Static rules cannot reliably detect stylistic mimicry or context-dependent role confusion. The ICML paper specifically demonstrates that attacks succeed through style rather than explicit markers — regex alone misses these.

### 3. Semantic Analysis Only (No Static Rules)

**Rejected.** LLM-based analysis requires API access, incurs cost, adds latency, and cannot run in air-gapped CI environments. Static rules provide a fast, free baseline that catches the most obvious patterns.

### 4. Generic Markdown Parser for Cursor SKILL.md

**Rejected.** Generic markdown parsing loses structural awareness of Cursor's specific section semantics. A dedicated parser enables targeted analysis of instruction sections vs. example sections, reducing false positives from example content.

---

## References

- Ye, Cui, Hadfield-Menell. "Prompt Injection as Role Confusion." ICML 2026. [arxiv.org/abs/2603.12277](https://arxiv.org/abs/2603.12277)
- Skill-Inject Benchmark (2026). Attack success rates for skill-file prompt injection vectors.
- OWASP LLM Top 10 2025: LLM01 (Prompt Injection), LLM02 (Insecure Output Handling)
- MITRE ATLAS: AML.T0051 (LLM Prompt Injection), AML.T0054 (LLM Jailbreak)
