"""flow_verify.py — LLM-verify multi-file call-graph flows.

The graph has no argument-level taint, so the slice is the only precision
mechanism: every hop's *complete* method body is sent (never a window or
truncation). Oversized methods skip the flow rather than hide a call site.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from llm_client import call_llm, parse_llm_json_array

from pipeline.call_graph import Flow, FLOW_VERIFY_CAP, flow_to_dict
from pipeline.llm_file_scan import (
    SINGLE_CALL_CHAR_BUDGET,
    _RESPONSE_SCHEMA,
    normalize_finding,
    should_publish_finding,
)

_FLOW_SYSTEM = (
    "You are a senior application security engineer. You are shown a call-graph "
    "slice: the FULL method body of every hop from an entry method to a dangerous "
    "sink, in order, across one or more source files.\n\n"
    "The graph only proved that these methods call each other — not that a "
    "particular argument is tainted. Your job is to read the actual call "
    "expressions and decide whether untrusted input from the ENTRY hop reaches "
    "the SINK hop unsanitized.\n\n"
    "How to reason:\n"
    "- Name the untrusted SOURCE (entry parameter, request accessor, or — when "
    "told so — a public module-API parameter) and the dangerous SINK.\n"
    "- A sink fed only by literals, constants, enums, or values the code itself "
    "produced is not a vulnerability.\n"
    "- Parameterised queries (bound `?` / named parameters) are safe even when "
    "the surrounding code concatenates non-parameter fragments.\n"
    "- Do NOT invent hops, files, or line numbers that are not shown.\n"
    "- Report the sink line number exactly as numbered in the sink hop's body.\n"
    "- For every candidate decide true_positive or false_positive and always "
    "give a verdict_reason.\n\n"
    "Respond with a JSON array only. No prose, no markdown fences."
)


def _numbered_body(body: str, start_line: int) -> str:
    lines = body.splitlines() or [""]
    return "\n".join(f"{start_line + i}: {line}" for i, line in enumerate(lines))


def build_flow_slice(flow: Flow) -> Optional[str]:
    """Concatenate full method bodies. None if any hop exceeds the char budget."""
    blocks: List[str] = []
    for hop in flow.hops:
        if len(hop.body) > SINGLE_CALL_CHAR_BUDGET:
            return None
        header = (
            f"--- {hop.file} {hop.method} "
            f"(L{hop.start_line}-{hop.end_line}) role={hop.role} ---"
        )
        blocks.append(f"{header}\n{_numbered_body(hop.body, hop.start_line)}")
    return "\n\n".join(blocks)


def build_flow_user_prompt(flow: Flow, slice_text: str) -> str:
    files = ", ".join(flow.files)
    hop_summary = " → ".join(h.method for h in flow.hops)
    source_note = (
        "The source is untrusted because it is a public API parameter of this "
        "module, not an HTTP request."
        if flow.entry_tier == "public_api"
        else "The source is untrusted input at the entry hop (HTTP, listener, or main)."
    )
    return (
        f"Flow: {hop_summary}\n"
        f"Entry tier: {flow.entry_tier}\n"
        f"Files: {files}\n"
        f"{source_note}\n\n"
        f"{slice_text}\n\n"
        f"{_RESPONSE_SCHEMA}\n"
    )


def _flow_path_payload(flow: Flow) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []
    n = len(flow.hops)
    for i, hop in enumerate(flow.hops, start=1):
        if i == 1:
            role = "source"
        elif i == n:
            role = "sink"
        else:
            role = "hop"
        steps.append({
            "step": i,
            "file": hop.file,
            "method": hop.method,
            "line": hop.line,
            "start_line": hop.start_line,
            "role": role,
            "label": hop.label,
            "snippet": _numbered_body(hop.body, hop.start_line),
        })
    return steps


def _data_flow_line(flow: Flow) -> str:
    return " → ".join(f"{h.method}:{h.label}" for h in flow.hops)


def verify_flow(
    flow: Flow,
    *,
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    suppress_no_cwe: bool = True,
    suppress_http_findings: bool = False,
    suppress_low_confidence_false_positives: bool = False,
) -> Dict[str, Any]:
    """LLM-verify one flow. Returns {findings, skipped, skip_reason}."""
    slice_text = build_flow_slice(flow)
    if slice_text is None:
        return {"findings": [], "skipped": True, "skip_reason": "slice_too_large"}

    system = f"{_FLOW_SYSTEM}\n\nTech stack: {stack_context or 'unknown'}"
    user = build_flow_user_prompt(flow, slice_text)
    raw = call_llm_fn(
        system, user, usage=usage, step="verify_flow_slices",
        provider=llm_provider, model=llm_model, json_mode=True,
    )
    items, parse_err = parse_llm_json_array(raw)
    if parse_err and not items:
        raw = call_llm_fn(
            system, user + "\n\nReturn a JSON array only.",
            usage=usage, step="verify_flow_slices",
            provider=llm_provider, model=llm_model, json_mode=True,
        )
        items, parse_err = parse_llm_json_array(raw)

    sink = flow.hops[-1]
    source_lines = sink.body.splitlines()
    findings: List[Dict[str, Any]] = []
    flow_path = _flow_path_payload(flow)
    affected = list(flow.files)
    data_flow = _data_flow_line(flow)

    for raw_item in items:
        if isinstance(raw_item, dict):
            raw_item = {**raw_item, "kind": "flow"}
        finding = normalize_finding(
            raw_item,
            file_path=sink.file,
            chunk_start=sink.start_line,
            chunk_end=sink.end_line,
            source_lines=source_lines,
            kind="flow",
        )
        if finding is None:
            continue
        finding["kind"] = "flow"
        finding["file_path"] = sink.file
        finding["line"] = finding.get("line") or sink.line
        finding["snippet"] = sink.body
        finding["data_flow"] = (finding.get("data_flow") or data_flow)[:600]
        finding["affected_files"] = affected
        finding["flow_path"] = flow_path
        if not finding.get("source"):
            finding["source"] = flow.hops[0].label
        if not finding.get("sink"):
            finding["sink"] = sink.label
        if should_publish_finding(
            finding, sink.body,
            suppress_no_cwe=suppress_no_cwe,
            suppress_http_findings=suppress_http_findings,
            suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
        ):
            findings.append(finding)
    return {"findings": findings, "skipped": False, "skip_reason": parse_err}


def verify_flows(
    flows: List[Flow],
    *,
    stack_context: str = "",
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Callable[..., str] = call_llm,
    findings_writer: Optional[Callable[[str, List[Dict[str, Any]]], None]] = None,
    cap: int = FLOW_VERIFY_CAP,
    suppress_no_cwe: bool = True,
    suppress_http_findings: bool = False,
    suppress_low_confidence_false_positives: bool = False,
    on_flow: Optional[Callable[[Flow, Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    selected = flows[: max(0, cap)]
    file_results: List[Dict[str, Any]] = []
    skipped_large = 0
    all_findings: List[Dict[str, Any]] = []

    for flow in selected:
        outcome = verify_flow(
            flow,
            stack_context=stack_context,
            usage=usage,
            llm_provider=llm_provider,
            llm_model=llm_model,
            call_llm_fn=call_llm_fn,
            suppress_no_cwe=suppress_no_cwe,
            suppress_http_findings=suppress_http_findings,
            suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
        )
        if outcome.get("skipped"):
            skipped_large += 1
            if on_flow is not None:
                on_flow(flow, outcome)
            continue
        sink_file = flow.hops[-1].file
        findings = outcome["findings"]
        all_findings.extend(findings)
        if findings_writer is not None and findings:
            findings_writer(sink_file, findings)
        file_results.append({
            "file_path": sink_file,
            "findings": findings,
            "tp_count": sum(1 for f in findings if f.get("verdict") == "true_positive"),
            "fp_count": sum(1 for f in findings if f.get("verdict") == "false_positive"),
            "chunk_errors": [],
            "flow": flow_to_dict(flow),
        })
        if on_flow is not None:
            on_flow(flow, outcome)

    return {
        "files_scanned": len(file_results),
        "flows_verified": len(selected) - skipped_large,
        "flows_skipped_large": skipped_large,
        "tp_count": sum(r["tp_count"] for r in file_results),
        "fp_count": sum(r["fp_count"] for r in file_results),
        "files": file_results,
        "findings": all_findings,
    }
