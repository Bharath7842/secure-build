"""dep_classify.py — label the dependencies no framework signature matched.

`dependency_scan` matches declared dependencies against `stack_signatures`;
whatever it cannot match used to be reduced to a count and 20 sample names, so
a library that *is* a known framework under another coordinate (a fork, a
scoped package, a wrapper) never switched on the rules and surfaces filtered
on that framework label.

One LLM call maps the unmatched dependencies onto labels that already exist in
`stack_signatures.SIGNATURES` (the only labels a rule's `frameworks` filter can
match). The result is additive only: it is kept apart from
`dependency_summary["frameworks"]` so the tech-stack verdict, project type and
confidence — and the prompts and cache keys built from them — do not move, and
it is only ever unioned into the set of active framework labels, which can
widen which rules and surfaces apply and never narrows them. Any failure
returns no labels.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from llm_client import call_llm, parse_llm_json_array

from pipeline import stack_signatures

LLM_STEP = "classify_dependencies"
MAX_TOKENS_CEILING = 4096
TOKENS_PER_DEPENDENCY = 40
TOKEN_HEADROOM = 200

_SYSTEM = (
    "You label software dependencies. You are given a list of allowed framework "
    "labels and a list of declared dependencies that no rule has recognised. "
    "For each dependency that IS one of the allowed frameworks (the framework "
    "itself, a fork or republished build of it, or one of its official "
    "sub-packages), answer with that exact label. Skip every dependency that "
    "is merely related, a plugin for it, a utility library, or unknown to you. "
    "Precision matters more than coverage: when unsure, omit the dependency. "
    "Never invent a label and never use one that is not in the allowed list.\n"
    'Respond with one JSON object only: {"decisions": [{"dependency": '
    '"<ecosystem>:<name>", "label": "<allowed label>"}]}. An empty list is a '
    "valid answer."
)


def _label_index() -> Dict[str, Dict[str, Any]]:
    """label -> {category, ecosystems}, from the signature table."""
    index: Dict[str, Dict[str, Any]] = {}
    for sig in stack_signatures.SIGNATURES:
        entry = index.setdefault(sig["label"], {"category": sig["category"], "ecosystems": set()})
        entry["ecosystems"].add(sig["ecosystem"])
    return index


def _dep_key(dep: Dict[str, Any]) -> str:
    return f"{dep['ecosystem']}:{dep['name']}"


def build_user_prompt(deps: List[Dict[str, Any]], labels_by_ecosystem: Dict[str, List[str]]) -> str:
    lines = ["Allowed labels by ecosystem:"]
    for eco in sorted(labels_by_ecosystem):
        lines.append(f"- {eco}: {', '.join(sorted(labels_by_ecosystem[eco]))}")
    lines.append("")
    lines.append("Dependencies:")
    for dep in deps:
        version = dep.get("version")
        lines.append(f"- {_dep_key(dep)}" + (f"@{version}" if version else ""))
    return "\n".join(lines)


def classify_unrecognized(
    deps: List[Dict[str, Any]],
    *,
    usage: Optional[Dict[str, Any]] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    call_llm_fn: Optional[Callable[..., str]] = None,
) -> List[Dict[str, Any]]:
    """Return `dependency_summary["llm_labels"]`-shaped entries, or [] on any problem.

    `deps` is `dependency_summary["unrecognized_dependencies"]` (already sorted
    and deduped, which keeps the prompt byte-stable for the result cache)."""
    if not deps:
        return []
    call_llm_fn = call_llm_fn or call_llm  # resolved at call time so tests can patch call_llm
    index = _label_index()
    ecosystems = {d["ecosystem"] for d in deps}
    labels_by_ecosystem: Dict[str, List[str]] = {
        eco: [label for label, meta in index.items() if eco in meta["ecosystems"]]
        for eco in ecosystems
    }
    labels_by_ecosystem = {eco: labels for eco, labels in labels_by_ecosystem.items() if labels}
    if not labels_by_ecosystem:
        return []
    deps = [d for d in deps if d["ecosystem"] in labels_by_ecosystem]
    if not deps:
        return []

    user = build_user_prompt(deps, labels_by_ecosystem)
    max_tokens = min(MAX_TOKENS_CEILING, TOKEN_HEADROOM + TOKENS_PER_DEPENDENCY * len(deps))
    try:
        raw = call_llm_fn(
            _SYSTEM, user, usage=usage, step=LLM_STEP,
            provider=llm_provider, model=llm_model, json_mode=True,
            max_tokens=max_tokens,
        )
        items, parse_err = parse_llm_json_array(raw)
        if parse_err and not items:
            raw = call_llm_fn(
                _SYSTEM, user + '\n\nReturn the {"decisions": [...]} JSON object only.',
                usage=usage, step=LLM_STEP,
                provider=llm_provider, model=llm_model, json_mode=True,
                max_tokens=max_tokens,
            )
            items, parse_err = parse_llm_json_array(raw)
    except Exception:  # noqa: BLE001 — classification must never fail the scan (incl. LlmBudgetExhausted)
        return []
    return _validated_labels(items, deps, index)


def _validated_labels(
    items: Any, deps: List[Dict[str, Any]], index: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Keep only answers naming a dependency we sent and a label valid for its ecosystem."""
    if not isinstance(items, list):
        return []
    by_key = {_dep_key(d): d for d in deps}
    grouped: Dict[str, Dict[str, Any]] = {}
    seen: Set[Tuple[str, str]] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = str(item.get("dependency") or "").strip()
        label = str(item.get("label") or "").strip()
        dep = by_key.get(key)
        meta = index.get(label)
        if dep is None or meta is None or dep["ecosystem"] not in meta["ecosystems"]:
            continue
        if (label, key) in seen:
            continue
        seen.add((label, key))
        entry = grouped.setdefault(label, {
            "label": label,
            "category": meta["category"],
            "ecosystem": dep["ecosystem"],
            "matched_dependencies": [],
            "source": "llm",
        })
        entry["matched_dependencies"].append({"name": dep["name"], "version": dep.get("version")})
    return sorted(grouped.values(), key=lambda e: e["label"])


def active_framework_labels(dependency_summary: Optional[Dict[str, Any]]) -> Set[str]:
    """Signature-matched labels plus the additive LLM-classified ones."""
    summary = dependency_summary or {}
    labels = {f["label"] for f in summary.get("frameworks", [])}
    labels.update(f["label"] for f in summary.get("llm_labels", []))
    return labels
