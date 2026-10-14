"""RepoDossier: the bounded, deterministic summary that stands in for "the
repository" in every hunt prompt. Built without any LLM call.

On a 30k-file repo the model never sees a file list — it sees stack and
surfaces, how many entry points and sinks of each kind exist and where they
cluster, which security-config files exist, and what the catalog pass already
flagged. Everything else it must go and search for.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence

from pipeline.call_graph import _is_framework_entry, _is_test_path
from pipeline.hunt import catalog
from pipeline.hunt.rg_runner import RgRunner
from pipeline.hunt.symbols import SymbolService

DOSSIER_MAX_CHARS = 24_000  # ~6k tokens
_RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_SECURITY_CONFIG_RE = re.compile(
    r"(SecurityConfig|WebSecurityConfig|SecurityFilterChain|AuthConfig|WebMvcConfig|CorsConfig)\w*\.java$"
    r"|(^|/)(web\.xml|security\.xml|applicationContext-security\.xml|application(-\w+)?\.(properties|ya?ml))$"
    r"|Filter\w*\.java$|Interceptor\w*\.java$",
    re.IGNORECASE,
)


@dataclass
class SinkInventory:
    kind: str
    file_count: int
    top_files: List[str]
    resolution: str  # graph | textual


@dataclass
class RepoDossier:
    stack: str
    frameworks: List[str]
    surfaces: List[Dict[str, str]]
    modules: List[str]
    seed_counts: Dict[str, int]
    entry_point_count: int
    entry_points: List[str]
    sinks: List[SinkInventory]
    security_config_files: List[str]
    catalog_hits: List[Dict[str, Any]]
    flow_candidates: List[str]
    has_call_graph: bool
    has_joern: bool
    notes: List[str] = field(default_factory=list)

    def sink_kinds_present(self) -> List[str]:
        return [s.kind for s in self.sinks if s.file_count > 0]

    def render(self, max_chars: int = DOSSIER_MAX_CHARS) -> str:
        out: List[str] = []
        out.append(f"Stack: {self.stack or 'unknown'}")
        if self.frameworks:
            out.append(f"Frameworks: {', '.join(self.frameworks[:20])}")
        out.append(
            "Analysis available: "
            + ("call graph (receiver-type resolved)" if self.has_call_graph else "no call graph (text search only)")
            + ("; Joern taint paths" if self.has_joern else "")
        )
        if self.seed_counts:
            out.append(
                "Files to hunt in (non-CRITICAL tier): "
                + ", ".join(f"{k} {v}" for k, v in sorted(self.seed_counts.items(), key=lambda kv: _RISK_ORDER.get(kv[0], 9)))
            )
        if self.modules:
            out.append(f"Modules ({len(self.modules)}): {', '.join(self.modules[:25])}")
        if self.surfaces:
            out.append("Active vulnerability surfaces:")
            out.extend(f"  - {s['surface']}: {s['rationale']}" for s in self.surfaces[:20])
        out.append(f"Entry points ({self.entry_point_count}):")
        out.extend(f"  - {e}" for e in self.entry_points[:15])
        if self.sinks:
            out.append("Sink inventory (files containing each kind; 'textual' counts are approximate):")
            for s in self.sinks:
                if s.file_count:
                    out.append(
                        f"  - {s.kind}: {s.file_count} file(s) [{s.resolution}]"
                        + (f" e.g. {', '.join(s.top_files[:3])}" if s.top_files else "")
                    )
        if self.security_config_files:
            out.append("Security configuration files:")
            out.extend(f"  - {f}" for f in self.security_config_files[:12])
        if self.catalog_hits:
            out.append("Already flagged by the regex catalog (rule: hits):")
            out.extend(f"  - {h['rule_id']}: {h['count']}" for h in self.catalog_hits[:15])
        if self.flow_candidates:
            out.append("Unconfirmed cross-file flows from static analysis:")
            out.extend(f"  - {f}" for f in self.flow_candidates[:10])
        out.extend(self.notes)
        text = "\n".join(out)
        if len(text) > max_chars:
            text = text[: max_chars - 40].rsplit("\n", 1)[0] + "\n  ... (dossier truncated)"
        return text


def _module_of(path: str) -> str:
    parts = PurePosixPath(path).parts
    if "src" in parts:
        idx = parts.index("src")
        return "/".join(parts[:idx]) or "(root)"
    return parts[0] if len(parts) > 1 else "(root)"


def _rank_files(files: Iterable[str], risk_by_path: Dict[str, str]) -> List[str]:
    return sorted(
        set(files),
        key=lambda f: (_is_test_path(f), _RISK_ORDER.get(risk_by_path.get(f, ""), 4), f),
    )


def build_dossier(
    *,
    runner: RgRunner,
    symbols: SymbolService,
    stack: str,
    frameworks: Sequence[str] = (),
    surfaces: Sequence[Any] = (),
    seed_entries: Sequence[Dict[str, Any]] = (),
    inventory: Sequence[str] = (),
    catalog_hits: Optional[Dict[str, int]] = None,
    flow_candidates: Sequence[Dict[str, Any]] = (),
) -> RepoDossier:
    risk_by_path = {e["path"]: str(e.get("risk_level") or "") for e in seed_entries if e.get("path")}
    seed_counts = dict(Counter(risk_by_path.values()))
    modules = sorted({_module_of(p) for p in inventory}) if inventory else []

    graph = symbols.graph
    entries: List[str] = []
    entry_count = 0
    if graph is not None:
        framework_entries = [m for m in graph.methods.values() if _is_framework_entry(m) and not _is_test_path(m.file)]
        entry_count = len(framework_entries)
        for m in sorted(framework_entries, key=lambda m: (m.file, m.start_line))[:15]:
            anns = ",".join(f"@{a}" for a in m.annotations[:2])
            entries.append(f"{m.file}:{m.start_line} {m.fqcn.rsplit('.', 1)[-1]}.{m.name} {anns}".strip())
    else:
        result = runner.search(catalog.ENTRY_ANNOTATION_PATTERN, trusted=True, max_count_per_file=20)
        entry_count = result.match_count
        for m in sorted(result.matches, key=lambda m: (_is_test_path(m.file), m.file, m.line))[:15]:
            entries.append(f"{m.file}:{m.line} {m.text.strip()[:100]}")

    sinks: List[SinkInventory] = []
    graph_kinds: Dict[str, List[str]] = {}
    if graph is not None:
        for sink in graph.sinks:
            graph_kinds.setdefault(sink.kind, []).append(sink.file)
    for kind, patterns in catalog.sink_patterns().items():
        if kind in graph_kinds:
            files = graph_kinds[kind]
            resolution = "graph"
        else:
            combined = "|".join(f"(?:{p})" for p in patterns)
            result = runner.files_with_matches(combined, trusted=True)
            files = result.files if result.ok else []
            resolution = "textual"
        ranked = _rank_files(files, risk_by_path)
        sinks.append(SinkInventory(kind=kind, file_count=len(set(files)), top_files=ranked[:3], resolution=resolution))

    security_files = [p for p in inventory if _SECURITY_CONFIG_RE.search(p) and not _is_test_path(p)]

    hits = sorted((catalog_hits or {}).items(), key=lambda kv: -kv[1])
    flows = []
    for f in flow_candidates[:10]:
        hops = f.get("hops") or []
        if len(hops) >= 2:
            flows.append(
                f"{f.get('sink_kind')}: {hops[0].get('file')}:{hops[0].get('line')} -> "
                f"{hops[-1].get('file')}:{hops[-1].get('line')} ({f.get('entry_tier')})"
            )

    surface_rows = []
    for s in surfaces:
        name = getattr(s, "surface", None) or (s.get("surface") if isinstance(s, dict) else None)
        if name:
            rationale = getattr(s, "rationale", None) or (s.get("rationale") if isinstance(s, dict) else "")
            surface_rows.append({"surface": str(name), "rationale": str(rationale or "")[:200]})

    return RepoDossier(
        stack=stack,
        frameworks=list(frameworks),
        surfaces=surface_rows,
        modules=modules,
        seed_counts=seed_counts,
        entry_point_count=entry_count,
        entry_points=entries,
        sinks=sinks,
        security_config_files=sorted(security_files)[:30],
        catalog_hits=[{"rule_id": k, "count": v} for k, v in hits[:30]],
        flow_candidates=flows,
        has_call_graph=graph is not None,
        has_joern=bool(symbols.joern_paths),
    )
