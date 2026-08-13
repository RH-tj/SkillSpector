# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Shared severity ranking and --min-severity helpers.

``min_severity`` is an analysis gate, not just a report filter: findings and
LLM work below the threshold should be skipped so scans spend fewer tokens.
"""

from __future__ import annotations

from collections.abc import Sequence

from skillspector.models import Finding

# Higher rank = more severe.
SEVERITY_RANK: dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

# LLM analyzers whose findings are overwhelmingly below HIGH. When the user
# asks for HIGH+, skip these nodes entirely to avoid N file LLM calls.
_LOW_YIELD_LLM_ANALYZERS_AT_HIGH: frozenset[str] = frozenset(
    {
        "semantic_quality_policy",
    }
)


def normalize_severity(severity: str | None) -> str:
    """Return an uppercased severity, defaulting unknown/empty to LOW."""
    if not severity:
        return "LOW"
    return severity.upper()


def normalize_min_severity(min_severity: str | None) -> str:
    """Normalize a min-severity threshold; unset means LOW (no filtering)."""
    return normalize_severity(min_severity)


def severity_rank(severity: str | None) -> int:
    """Numeric rank for comparisons; unknown severities rank as LOW."""
    return SEVERITY_RANK.get(normalize_severity(severity), 0)


def meets_min_severity(severity: str | None, min_severity: str | None) -> bool:
    """Return True when *severity* is at or above *min_severity*."""
    return severity_rank(severity) >= severity_rank(min_severity)


def is_severityity_filter_active(min_severity: str | None) -> bool:
    """True when the threshold excludes at least one severity band."""
    return normalize_min_severity(min_severity) != "LOW"


def filter_findings_by_min_severity(
    findings: Sequence[Finding],
    min_severity: str | None,
) -> tuple[list[Finding], int]:
    """Keep findings at or above *min_severity*; return ``(kept, dropped_count)``.

    ``None`` or ``LOW`` keeps every finding.
    """
    if not is_severityity_filter_active(min_severity):
        return list(findings), 0
    kept = [f for f in findings if meets_min_severity(f.severity, min_severity)]
    return kept, len(findings) - len(kept)


def should_skip_llm_analyzer(analyzer_id: str, min_severity: str | None) -> bool:
    """Return True when an LLM analyzer should not run for this threshold."""
    if not is_severityity_filter_active(min_severity):
        return False
    if severity_rank(min_severity) < SEVERITY_RANK["HIGH"]:
        return False
    return analyzer_id in _LOW_YIELD_LLM_ANALYZERS_AT_HIGH


def severity_constraint_prompt(min_severity: str | None) -> str:
    """Extra prompt text instructing the LLM to only emit at/above threshold.

    Empty string when no filter is active (default LOW).
    """
    if not is_severityity_filter_active(min_severity):
        return ""
    threshold = normalize_min_severity(min_severity)
    return (
        f"\n## Severity filter (mandatory)\n\n"
        f"ONLY report findings with severity {threshold} or higher "
        f"(severity rank: LOW < MEDIUM < HIGH < CRITICAL). "
        f"Do NOT report LOW"
        + (" or MEDIUM" if severity_rank(threshold) >= SEVERITY_RANK["HIGH"] else "")
        + " findings. If nothing meets this bar, return "
        '{"findings": []}.\n'
    )


def min_severity_skip_notice(dropped_count: int, min_severity: str | None) -> str | None:
    """Human-readable note when findings were omitted by --min-severity."""
    if dropped_count <= 0 or not is_severityity_filter_active(min_severity):
        return None
    noun = "finding" if dropped_count == 1 else "findings"
    return (
        f"{dropped_count} {noun} below {normalize_min_severity(min_severity)} "
        f"skipped (--min-severity)"
    )
