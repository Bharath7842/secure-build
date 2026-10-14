"""flow_verify.py — LLM-verify multi-file call-graph flows.

The graph has no argument-level taint, so the slice is the only precision
mechanism: every hop's *complete* method body is sent. Oversized methods skip
the flow rather than hide a call site. The one exception is a slice over
FLOW_SLICE_CHAR_BUDGET in total: its *intermediate* hops are condensed to the
signature plus a window around the call into the next hop (and any Joern path
line), while the entry and sink hops always stay whole.

Flows that share hop methods are verified together (up to FLOWS_PER_CALL per
call), so a method common to several flows — typically a DAO/repository sink
reached from several controllers — is sent once instead of once per flow.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from llm_client import call_llm, parse_llm_json_array

from pipeline import reachability
from pipeline.call_graph import Flow, FLOW_VERIFY_CAP, flow_to_dict
from pipeline.llm_file_scan import (
    SINGLE_CALL_CHAR_BUDGET,
    _RESPONSE_SCHEMA,
    normalize_finding,
    should_publish_finding,
)

# Total slice size above which intermediate hops are condensed.
FLOW_SLICE_CHAR_BUDGET = 32_000
# Lines kept either side of a condensed hop's call line / Joern path line.
CONDENSED_HOP_WINDOW = 8
# Flows sharing at least one hop are batched into one call, up to this many
# flows and FLOW_GROUP_CHAR_BUDGET characters of (deduplicated) hop code.
FLOWS_PER_CALL = 3
FLOW_GROUP_CHAR_BUDGET = 24_000

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
    "give a verdict_reason.\n"
    "- When several flows are shown, every finding must carry the flow_id it "
    "belongs to; shared hops are listed once and referenced by id.\n\n"
    "Respond with the JSON object described under Output format only. No prose, "
    "no markdown fences."
)

_FLOW_ID_SCHEMA_NOTE = (
    'When the prompt lists several flows (F1, F2, ...), add "flow_id": "<F1|F2|...>" '
    "to every finding."
)


def build_flow_system_prompt(stack_context: str = "") -> str:
    return (
        f"{_FLOW_SYSTEM}\n\n{_RESPONSE_SCHEMA}\n{_FLOW_ID_SCHEMA_NOTE}\n\n"
        f"Tech stack: {stack_context or 'unknown'}"
    )


def _numbered_body(body: str, start_line: int) -> str:
    lines = body.splitlines() or [""]
    return "\n".join(f"{start_line + i}: {line}" for i, line in enumerate(lines))


def _hop_header(hop: Any, condensed: bool = False) -> str:
    note = " condensed" if condensed else ""
    return (
        f"--- {hop.file} {hop.method} "
        f"(L{hop.start_line}-{hop.end_line}) role={hop.role}{note} ---"
    )


def _condensed_body(hop: Any, keep_lines: List[int]) -> str:
    """Signature line plus numbered windows around `keep_lines`, with
    `…` marking each gap. Line numbers stay true to the file."""
    lines = hop.body.splitlines() or [""]
    keep = {0}
    for target in keep_lines:
        idx = target - hop.start_line
        for i in range(idx - CONDENSED_HOP_WINDOW, idx + CONDENSED_HOP_WINDOW + 1):
            if 0 <= i < len(lines):
                keep.add(i)
    out: List[str] = []
    prev = -1
    for i in sorted(keep):
        if prev >= 0 and i != prev + 1:
            out.append("…")
        out.append(f"{hop.start_line + i}: {lines[i]}")
        prev = i
    if prev < len(lines) - 1:
        out.append("…")
    return "\n".join(out)


def _taint_lines_for_hop(flow: Flow, hop: Any) -> List[int]:
    return [
        int(step.get("line") or -1)
        for step in flow.taint_path
        if step.get("file") == hop.file
        and hop.start_line <= int(step.get("line") or -1) <= hop.end_line
    ]


def build_hop_blocks(flow: Flow) -> Optional[List[Tuple[Tuple[str, str, int], str]]]:
    """[(hop_key, rendered block)] in hop order, or None if any single hop
    exceeds SINGLE_CALL_CHAR_BUDGET (the flow is skipped, never truncated)."""
    if any(len(hop.body) > SINGLE_CALL_CHAR_BUDGET for hop in flow.hops):
        return None
    total = sum(len(hop.body) for hop in flow.hops)
    last = len(flow.hops) - 1
    blocks: List[Tuple[Tuple[str, str, int], str]] = []
    for i, hop in enumerate(flow.hops):
        condense = total > FLOW_SLICE_CHAR_BUDGET and 0 < i < last
        if condense:
            body = _condensed_body(hop, [hop.line] + _taint_lines_for_hop(flow, hop))
            condense = len(body) < len(hop.body)
        if not condense:
            body = _numbered_body(hop.body, hop.start_line)
        key = (hop.file, hop.method, hop.start_line)
        blocks.append((key, f"{_hop_header(hop, condense)}\n{body}"))
    return blocks


def build_flow_slice(flow: Flow) -> Optional[str]:
    """Concatenated hop bodies. None if any hop exceeds the char budget."""
    blocks = build_hop_blocks(flow)
    if blocks is None:
        return None
    return "\n\n".join(text for _key, text in blocks)


_TAINT_PATH_MAX_STEPS = 40


def build_taint_path_note(flow: Flow) -> str:
    """Expression-level path for Joern flows; empty for method-level flows.

    Joern proved the value travels along these expressions, so the model's job
    narrows to whether any step sanitizes it — it no longer has to guess
    which argument carries the input.
    """
    if not flow.taint_path:
        return ""
    steps = flow.taint_path
    if len(steps) > _TAINT_PATH_MAX_STEPS:
        half = _TAINT_PATH_MAX_STEPS // 2
        steps = steps[:half] + [{"file": "...", "line": -1, "code": "..."}] + steps[-half:]
    lines = [
        f"  {s.get('file')}:L{s.get('line')}  {s.get('code')}" if s.get("line", -1) > 0
        else "  ..."
        for s in steps
    ]
    note = (
        "Dataflow path (Joern; each line is an expression the untrusted value "
        "flows through, in order — decide whether any step sanitizes it):\n"
        + "\n".join(lines)
        + "\n"
    )
    if flow.guards:
        note += (
            "Conditions this path is control-dependent on (Joern CDG — a check here "
            "that rejects bad input before the sink breaks the flow; a null/empty "
            "check does not):\n"
            + "\n".join(f"  {g.get('file')}:L{g.get('line')}  {g.get('code')}" for g in flow.guards)
            + "\n"
        )
    if flow.sanitizers:
        note += (
            "Known sanitizer calls on the path (confirm each actually neutralises "
            "this sink kind and covers the value that reaches it):\n"
            + "\n".join(f"  {s.get('file')}:L{s.get('line')}  {s.get('code')}" for s in flow.sanitizers)
            + "\n"
        )
    return note + "\n"


def build_other_sources_note(flow: Flow) -> str:
    """Entry points of flows collapsed into this one (same sink)."""
    if not flow.other_sources:
        return ""
    return (
        "Other entry points that reach this same sink (verified once here — it is "
        "exploitable if any entry point delivers unsanitized input to it):\n"
        + "\n".join(
            f"  {s.get('file')}:L{s.get('line')}  {s.get('method') or ''}  {s.get('label') or ''}".rstrip()
            for s in flow.other_sources
        )
        + "\n\n"
    )


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
        f"{build_taint_path_note(flow)}"
        f"{build_other_sources_note(flow)}"
        f"{slice_text}\n"
    )


def _source_note(flow: Flow) -> str:
    return (
        "public module-API parameter (not an HTTP request)"
        if flow.entry_tier == "public_api"
        else "untrusted input at the entry hop (HTTP, listener, or main)"
    )


def build_flow_group_user_prompt(
    flows: List[Flow], blocks_per_flow: List[List[Tuple[Tuple[str, str, int], str]]],
) -> str:
    """Several flows in one prompt: each distinct hop is printed once as
    [H<n>], and every flow is a line of hop references."""
    hop_ids: Dict[Tuple[str, str, int], str] = {}
    hop_texts: List[str] = []
    for blocks in blocks_per_flow:
        for key, text in blocks:
            if key not in hop_ids:
                hop_ids[key] = f"H{len(hop_ids) + 1}"
                hop_texts.append(f"[{hop_ids[key]}] {text}")
    flow_lines: List[str] = []
    for n, (flow, blocks) in enumerate(zip(flows, blocks_per_flow), start=1):
        chain = " → ".join(hop_ids[key] for key, _text in blocks)
        flow_lines.append(
            f"F{n}: {chain}  ({' → '.join(h.method for h in flow.hops)}; "
            f"entry tier {flow.entry_tier}; source is {_source_note(flow)})"
        )
        note = build_taint_path_note(flow) + build_other_sources_note(flow)
        if note:
            flow_lines.append(f"  F{n} " + note.rstrip())
    return (
        f"{len(flows)} flows share code. Judge each flow separately and tag every "
        "finding with its flow_id.\n\n"
        "Flows:\n" + "\n".join(flow_lines) + "\n\n"
        "Hops (each listed once):\n" + "\n\n".join(hop_texts) + "\n"
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


def _call_and_parse(
    system: str,
    user: str,
    *,
    usage: Optional[Dict[str, Any]],
    llm_provider: Optional[str],
    llm_model: Optional[str],
    call_llm_fn: Callable[..., str],
    step: str = "verify_flow_slices",
) -> Tuple[List[Any], Optional[str]]:
    # A raised call (transport failure after call_llm's own retries, or the
    # cost cutoff with no fallback) counts as a failed flow, not a dead scan.
    try:
        raw = call_llm_fn(
            system, user, usage=usage, step=step,
            provider=llm_provider, model=llm_model, json_mode=True,
        )
        items, parse_err = parse_llm_json_array(raw)
        if parse_err and not items:
            raw = call_llm_fn(
                system, user + '\n\nReturn the {"findings": [...]} JSON object only.',
                usage=usage, step=step,
                provider=llm_provider, model=llm_model, json_mode=True,
            )
            items, parse_err = parse_llm_json_array(raw)
    except Exception as exc:  # noqa: BLE001
        return [], f"{type(exc).__name__}: {exc}"
    return items, parse_err


def _findings_for_flow(
    flow: Flow,
    items: List[Any],
    *,
    suppress_no_cwe: bool,
    suppress_http_findings: bool,
    suppress_low_confidence_false_positives: bool,
) -> List[Dict[str, Any]]:
    sink = flow.hops[-1]
    source_lines = sink.body.splitlines()
    findings: List[Dict[str, Any]] = []
    flow_path = _flow_path_payload(flow)
    affected = list(flow.files)
    data_flow = _data_flow_line(flow)
    # Joern flows carry the expression-level path; keep it as evidence rather
    # than only showing it to the model.
    evidence = reachability.evidence_from_flow(flow) if flow.taint_path else None

    for raw_item in items:
        if isinstance(raw_item, dict):
            raw_item = {**raw_item, "kind": "flow"}
            raw_item.pop("flow_id", None)
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
        if evidence is not None:
            finding["reachability"] = evidence
            reachability.apply_confidence(finding)
        if should_publish_finding(
            finding, sink.body,
            suppress_no_cwe=suppress_no_cwe,
            suppress_http_findings=suppress_http_findings,
            suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
        ):
            findings.append(finding)
    return findings


_FLOW_ID_RE = re.compile(r"F?\s*(\d+)", re.IGNORECASE)


def assign_items_to_flows(flows: List[Flow], items: List[Any]) -> List[List[Any]]:
    """Route a grouped response's findings to their flows: by flow_id when the
    model gave one, else to the first flow whose sink hop contains the line.
    Anything that matches neither is dropped (it cannot be attributed)."""
    per_flow: List[List[Any]] = [[] for _ in flows]
    for item in items:
        if not isinstance(item, dict):
            continue
        match = _FLOW_ID_RE.fullmatch(str(item.get("flow_id") or "").strip())
        if match and 1 <= int(match.group(1)) <= len(flows):
            per_flow[int(match.group(1)) - 1].append(item)
            continue
        try:
            line = int(item.get("line"))
        except (TypeError, ValueError):
            continue
        for i, flow in enumerate(flows):
            sink = flow.hops[-1]
            if sink.start_line <= line <= sink.end_line:
                per_flow[i].append(item)
                break
    return per_flow


def group_flows_by_shared_hops(
    prepared: List[Tuple[int, Flow, List[Tuple[Tuple[str, str, int], str]]]],
) -> List[List[int]]:
    """Greedy batching: a flow joins an open group only if it shares at least
    one hop with it, the group has room (FLOWS_PER_CALL), and the group's
    deduplicated hop code stays within FLOW_GROUP_CHAR_BUDGET. Unrelated flows
    are never batched — the saving comes from shared code, and keeping them
    apart keeps finding attribution unambiguous."""
    groups: List[Dict[str, Any]] = []
    for idx, _flow, blocks in prepared:
        sizes = {key: len(text) for key, text in blocks}
        placed = False
        for group in groups:
            if len(group["idxs"]) >= FLOWS_PER_CALL or not (sizes.keys() & group["keys"]):
                continue
            extra = sum(size for key, size in sizes.items() if key not in group["keys"])
            if group["chars"] + extra > FLOW_GROUP_CHAR_BUDGET:
                continue
            group["idxs"].append(idx)
            group["keys"] |= set(sizes)
            group["chars"] += extra
            placed = True
            break
        if not placed:
            groups.append({"idxs": [idx], "keys": set(sizes), "chars": sum(sizes.values())})
    return [group["idxs"] for group in groups]


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
    """LLM-verify one flow. Returns {findings, skipped, skip_reason, failed}."""
    slice_text = build_flow_slice(flow)
    if slice_text is None:
        return {"findings": [], "skipped": True, "skip_reason": "slice_too_large"}
    items, parse_err = _call_and_parse(
        build_flow_system_prompt(stack_context), build_flow_user_prompt(flow, slice_text),
        usage=usage, llm_provider=llm_provider, llm_model=llm_model, call_llm_fn=call_llm_fn,
    )
    findings = _findings_for_flow(
        flow, items,
        suppress_no_cwe=suppress_no_cwe,
        suppress_http_findings=suppress_http_findings,
        suppress_low_confidence_false_positives=suppress_low_confidence_false_positives,
    )
    return {
        "findings": findings, "skipped": False, "skip_reason": parse_err,
        "failed": bool(parse_err and not items),
    }


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
    flows_per_call: int = FLOWS_PER_CALL,
    llm_step: str = "verify_flow_slices",
) -> Dict[str, Any]:
    selected = flows[: max(0, cap)]
    suppress = {
        "suppress_no_cwe": suppress_no_cwe,
        "suppress_http_findings": suppress_http_findings,
        "suppress_low_confidence_false_positives": suppress_low_confidence_false_positives,
    }
    outcomes: List[Optional[Dict[str, Any]]] = [None] * len(selected)
    prepared: List[Tuple[int, Flow, List[Tuple[Tuple[str, str, int], str]]]] = []
    for idx, flow in enumerate(selected):
        blocks = build_hop_blocks(flow)
        if blocks is None:
            outcomes[idx] = {"findings": [], "skipped": True, "skip_reason": "slice_too_large"}
        else:
            prepared.append((idx, flow, blocks))

    by_idx = {idx: (flow, blocks) for idx, flow, blocks in prepared}
    groups = (
        group_flows_by_shared_hops(prepared) if flows_per_call > 1
        else [[idx] for idx, _flow, _blocks in prepared]
    )
    system = build_flow_system_prompt(stack_context)
    llm_calls = 0
    file_results: List[Tuple[int, Dict[str, Any]]] = []
    all_findings: List[Dict[str, Any]] = []

    def _emit(idx: int) -> None:
        flow = selected[idx]
        outcome = outcomes[idx] or {}
        if outcome.get("skipped"):
            if on_flow is not None:
                on_flow(flow, outcome)
            return
        sink_file = flow.hops[-1].file
        findings = outcome["findings"]
        all_findings.extend(findings)
        if findings_writer is not None and findings:
            findings_writer(sink_file, findings)
        file_results.append((idx, {
            "file_path": sink_file,
            "findings": findings,
            "tp_count": sum(1 for f in findings if f.get("verdict") == "true_positive"),
            "fp_count": sum(1 for f in findings if f.get("verdict") == "false_positive"),
            "chunk_errors": [outcome["skip_reason"]] if outcome.get("failed") else [],
            "flow": flow_to_dict(flow),
        }))
        if on_flow is not None:
            on_flow(flow, outcome)

    for group in groups:
        group_flows = [by_idx[idx][0] for idx in group]
        group_blocks = [by_idx[idx][1] for idx in group]
        if len(group) == 1:
            user = build_flow_user_prompt(
                group_flows[0], "\n\n".join(text for _key, text in group_blocks[0]),
            )
        else:
            user = build_flow_group_user_prompt(group_flows, group_blocks)
        items, parse_err = _call_and_parse(
            system, user, usage=usage, llm_provider=llm_provider, llm_model=llm_model,
            call_llm_fn=call_llm_fn, step=llm_step,
        )
        llm_calls += 1
        per_flow = [items] if len(group) == 1 else assign_items_to_flows(group_flows, items)
        for idx, flow, flow_items in zip(group, group_flows, per_flow):
            outcomes[idx] = {
                "findings": _findings_for_flow(flow, flow_items, **suppress),
                "skipped": False,
                "skip_reason": parse_err,
                "failed": bool(parse_err and not items),
            }
        for idx in group:
            _emit(idx)

    for idx, outcome in enumerate(outcomes):
        if outcome is not None and outcome.get("skipped"):
            _emit(idx)

    ordered = [result for _idx, result in sorted(file_results, key=lambda pair: pair[0])]
    skipped_large = sum(1 for o in outcomes if o is not None and o.get("skipped"))
    failed = sum(1 for o in outcomes if o is not None and o.get("failed"))
    return {
        "files_scanned": len(ordered),
        # A flow whose response could not be parsed (even after the retry) was
        # attempted, not verified — it is counted in flows_failed instead.
        "flows_verified": len(selected) - skipped_large - failed,
        "flows_failed": failed,
        "flows_skipped_large": skipped_large,
        "llm_calls": llm_calls,
        "tp_count": sum(r["tp_count"] for r in ordered),
        "fp_count": sum(r["fp_count"] for r in ordered),
        "files": ordered,
        "findings": all_findings,
    }
