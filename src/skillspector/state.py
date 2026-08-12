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

"""State schema for the Skillspector LangGraph workflow."""

from __future__ import annotations

import operator
from typing import Annotated

from typing_extensions import TypedDict

from skillspector.inspection_ledger import AnalyzerStatusEvent, InspectionLedgerEvent
from skillspector.models import Finding

LLMCallRecord = dict[str, object]
InferenceUsageRecord = dict[str, object]
AnalysisCompleteness = dict[str, object]


class SkillspectorState(TypedDict, total=False):
    """Graph state shared by all nodes."""

    # Input: resolve_input node consumes input_path or skill_path, sets skill_path
    input_path: str | None
    skill_path: str | None
    # Set by resolve_input when a temp dir was created (git/url/zip/file); caller should clean up
    temp_dir_for_cleanup: str | None
    zip_bytes: bytes | None
    mode: str

    # build_context node populates these
    components: list[str]
    file_cache: dict[str, str]
    ast_cache: dict[str, str]
    python_ast_cache_key: str | None
    manifest: dict[str, object]
    previous_manifest: dict[str, object] | None

    # Accumulated findings (reducer: analyzer nodes append to this list)
    findings: Annotated[list[Finding], operator.add]
    filtered_findings: list[Finding]

    # Inspection ledger: execution accounting across all analyzer nodes
    inspection_ledger: Annotated[list[InspectionLedgerEvent], operator.add]
    analyzer_status_events: Annotated[list[AnalyzerStatusEvent], operator.add]
    effective_finding_ids: list[str]
    analysis_completeness: AnalysisCompleteness
    execution_successful: bool

    # Model IDs per LLM-using node: e.g. {"default": "...", "meta_analyzer": "..."}
    model_config: dict[str, str]

    # Component metadata for reporting and risk scoring (from build_context)
    component_metadata: list[dict[str, object]]
    has_executable_scripts: bool

    # Output: report node writes formatted string here
    output_format: str
    report_body: str

    # LLM: when False, LLM-based nodes (meta_analyzer, mcp_tool_poisoning's TP4,
    # and the semantic_* analyzers) return immediately without calling the LLM.
    # Each such node checks use_llm itself; there is no graph-level routing.
    use_llm: bool

    # Risk: report node sets these from risk_score
    risk_severity: str
    risk_recommendation: str

    sarif_report: dict[str, object]
    risk_score: int

    # Additional YARA rules directory (user-specified via --yara-rules-dir)
    yara_rules_dir: str | None

    # LLM call telemetry — each LLM-backed node appends one record per run.
    llm_call_log: Annotated[list[LLMCallRecord], operator.add]

    # Inference usage — provider-reported token counters per call.
    inference_usage: Annotated[list[InferenceUsageRecord], operator.add]

    # Baseline / false-positive suppression
    baseline: object | None
    baseline_path: str | None
    show_suppressed: bool
    suppressed_findings: list[object]


class AnalyzerNodeResponse(TypedDict):
    """Strict analyzer update payload for graph state."""

    findings: list[Finding]


class MetaAnalyzerResponse(TypedDict, total=False):
    """Strict meta-analyzer update payload for graph state."""

    filtered_findings: list[Finding]
    llm_call_log: list[LLMCallRecord]
    inspection_ledger: list[InspectionLedgerEvent]
    analyzer_status_events: list[AnalyzerStatusEvent]


def llm_call_record(
    node: str, *, ok: bool, error: str | None = None
) -> LLMCallRecord:
    """Build a telemetry record for the llm_call_log reducer."""
    rec: LLMCallRecord = {"node": node, "ok": ok}
    if error is not None:
        rec["error"] = error
    return rec
