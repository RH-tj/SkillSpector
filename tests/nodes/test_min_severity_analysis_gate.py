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

"""Tests for --min-severity analysis gating (meta + quality policy skip)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from skillspector.models import Finding
from skillspector.nodes.analyzers import semantic_quality_policy
from skillspector.nodes.meta_analyzer import meta_analyzer
from skillspector.state import SkillspectorState


def _finding(rule_id: str, severity: str, file: str = "SKILL.md") -> Finding:
    return Finding(
        rule_id=rule_id,
        message="test",
        severity=severity,
        confidence=1.0,
        file=file,
        start_line=1,
    )


def test_quality_policy_skipped_at_high_min_severity() -> None:
    state: SkillspectorState = {
        "use_llm": True,
        "min_severity": "HIGH",
        "file_cache": {"SKILL.md": "# hello"},
    }
    with patch.object(semantic_quality_policy, "LLMAnalyzerBase") as mock_cls:
        result = semantic_quality_policy.node(state)
    assert result == {"findings": []}
    mock_cls.assert_not_called()


def test_quality_policy_runs_at_medium_min_severity() -> None:
    state: SkillspectorState = {
        "use_llm": True,
        "min_severity": "MEDIUM",
        "file_cache": {"SKILL.md": "# hello"},
    }
    mock_analyzer = MagicMock()
    mock_analyzer.get_batches.return_value = []
    mock_analyzer.arun_batches = MagicMock()
    mock_analyzer.collect_findings.return_value = []

    with (
        patch.object(semantic_quality_policy, "LLMAnalyzerBase", return_value=mock_analyzer),
        patch.object(semantic_quality_policy.asyncio, "run", return_value=[]),
    ):
        result = semantic_quality_policy.node(state)
    assert result == {"findings": []}
    mock_analyzer.get_batches.assert_called_once()


def test_meta_analyzer_skips_llm_when_only_low_findings() -> None:
    state: SkillspectorState = {
        "use_llm": True,
        "min_severity": "HIGH",
        "findings": [_finding("L1", "LOW"), _finding("M1", "MEDIUM")],
        "file_cache": {"SKILL.md": "# content"},
        "manifest": {"name": "x"},
    }
    with patch("skillspector.nodes.meta_analyzer.LLMMetaAnalyzer") as mock_cls:
        result = meta_analyzer(state)
    assert result["filtered_findings"] == []
    mock_cls.assert_not_called()


def test_meta_analyzer_keeps_high_and_does_not_send_low() -> None:
    high = _finding("P1", "HIGH")
    low = _finding("L1", "LOW")
    state: SkillspectorState = {
        "use_llm": False,
        "min_severity": "HIGH",
        "findings": [high, low],
        "file_cache": {"SKILL.md": "# content"},
    }
    result = meta_analyzer(state)
    kept_ids = {f.rule_id for f in result["filtered_findings"]}
    assert kept_ids == {"P1"}
