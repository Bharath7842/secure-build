"""dependency_scan.py — orchestrates dependency-manifest parsing + signature
matching + config-file corroboration into one deterministic, LLM-free
tech-stack evidence pass.

Where the marker-file heuristic only says *which build tool* is present, and
ast_struct.py's tree-sitter pass only covers Java/Angular source structure,
this reads the *actual declared dependencies* for whatever ecosystem is
present — Maven, npm, pip, Go, Ruby, PHP, .NET, Rust — and matches them
against a curated signature table (stack_signatures.py) to name the real
framework stack. This is what closes the gap on non-Spring Java projects
(JAX-RS/RESTEasy/EJB/Struts/Axis2) and on every non-Java ecosystem
ast_struct.py never covers, without any LLM involvement.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from . import manifest_parsers
from . import stack_signatures

# Guard against pathological monorepos with thousands of manifest files —
# keeps this pass fast and bounded, same spirit as ast_struct.py's
# MAX_FILES_PER_STACK cap.
_MAX_MANIFESTS = 300

# Cap on the flat name+version list handed to rule dependency conditions. This
# list is what lets a rule say "only when commons-collections < 3.2.2 is
# declared" — such libraries are not *frameworks*, so they never appear under
# `frameworks` and would otherwise be invisible to the rule catalog.
_MAX_DECLARED_DEPENDENCIES = 600
_MAX_UNRECOGNIZED_DEPENDENCIES = 100

# Follow-up config-file checks, keyed to a matched signature's label/category/
# ecosystem — corroborates frameworks that are config-driven rather than
# code-driven (a `struts` dependency plus an actual struts-config.xml is
# stronger evidence than the dependency declaration alone). Mirrors exactly
# what the pasted transcript's assistant checked by hand (web.xml,
# jboss-ejb3.xml, jboss-web.xml, *.wsdl).
_CONFIG_COROBORATION_RULES: List[Dict[str, Any]] = [
    {
        "when_label_prefix": "Apache Struts",
        "file_patterns": ("struts-config.xml", "struts.xml"),
        "evidence": "Struts XML routing config found",
    },
    {
        "when_label_prefix": "Apache Axis2",
        "file_suffixes": (".wsdl",),
        "file_patterns": ("axis2.xml",),
        "evidence": "WSDL/Axis2 service descriptor found",
    },
    {
        "when_category": "web-framework",
        "when_ecosystem": "maven",
        "file_patterns": ("web.xml", "jboss-ejb3.xml", "jboss-web.xml"),
        "evidence": "Java EE deployment descriptor found",
    },
]


def _find_manifest_files(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    names = set(manifest_parsers.PARSERS_BY_FILENAME)
    exts = set(manifest_parsers.PARSERS_BY_EXT)
    return [f for f in scan["files"] if f["name"] in names or f["ext"] in exts]


def _read_text(root: Path, rel_path: str) -> Optional[str]:
    try:
        return (root / rel_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _corroborating_files(scan: Dict[str, Any], patterns: tuple = (), suffixes: tuple = ()) -> List[str]:
    hits = []
    for f in scan["files"]:
        name = f["name"]
        if name in patterns or any(name.endswith(suf) for suf in suffixes):
            hits.append(f["path"])
    return hits



def _unrecognized_list(unrecognized: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduped, sorted, capped copy of the dependencies no signature matched.
    Kept (unlike the old count + 20 samples) so a later step can classify them;
    sorted so a prompt built from it is byte-stable across runs."""
    seen = set()
    out: List[Dict[str, Any]] = []
    for dep in unrecognized:
        key = (dep["ecosystem"], dep["name"], dep.get("version"))
        if key in seen:
            continue
        seen.add(key)
        out.append({"ecosystem": dep["ecosystem"], "name": dep["name"], "version": dep.get("version")})
    out.sort(key=lambda d: (d["ecosystem"], d["name"].lower(), d["version"] or ""))
    return out[:_MAX_UNRECOGNIZED_DEPENDENCIES]

def analyze_dependencies(scan: Dict[str, Any], repo_root: Path) -> Optional[Dict[str, Any]]:
    """Runs the full dependency-manifest evidence pass.

    Returns None only when no manifest files were found at all — the same
    "nothing to say" contract ast_struct.build_ast_summary already uses, so
    callers can treat both the same way.
    """
    manifest_files = _find_manifest_files(scan)
    if not manifest_files:
        return None
    manifest_files = manifest_files[:_MAX_MANIFESTS]

    # Pre-read pom.xml <properties> across the whole repo so a child module's
    # ${property} placeholders can resolve against a parent pom found
    # elsewhere in the walk (best-effort, not full Maven inheritance).
    merged_pom_properties: Dict[str, str] = {}
    for f in manifest_files:
        if f["name"] != "pom.xml":
            continue
        text = _read_text(repo_root, f["path"])
        if text:
            merged_pom_properties.update(manifest_parsers.extract_pom_properties(text))

    all_deps: List[Dict[str, Any]] = []
    parsed_manifests: List[str] = []
    for f in manifest_files:
        text = _read_text(repo_root, f["path"])
        if text is None:
            continue
        if f["name"] == "pom.xml":
            deps = manifest_parsers.parse_pom_xml(text, merged_pom_properties)
        else:
            deps = manifest_parsers.parse_manifest(f["name"], f["ext"], text)
        if deps:
            parsed_manifests.append(f["path"])
        all_deps.extend(deps)

    recognized, unrecognized = stack_signatures.match_all(all_deps)

    frameworks_by_label: Dict[str, Dict[str, Any]] = {}
    for dep in recognized:
        label = dep["label"]
        entry = frameworks_by_label.setdefault(label, {
            "label": label,
            "category": dep["category"],
            "ecosystem": dep["ecosystem"],
            "matched_dependencies": [],
            "_seen": set(),
        })
        key = (dep["name"], dep.get("version"))
        if key not in entry["_seen"]:
            entry["_seen"].add(key)
            entry["matched_dependencies"].append({"name": dep["name"], "version": dep.get("version")})

    frameworks = sorted(
        [{k: v for k, v in entry.items() if k != "_seen"} for entry in frameworks_by_label.values()],
        key=lambda e: e["label"],
    )

    config_evidence: List[str] = []
    for entry in frameworks:
        for rule in _CONFIG_COROBORATION_RULES:
            label_prefix = rule.get("when_label_prefix")
            if label_prefix and not entry["label"].startswith(label_prefix):
                continue
            category = rule.get("when_category")
            if category and entry["category"] != category:
                continue
            ecosystem = rule.get("when_ecosystem")
            if ecosystem and entry["ecosystem"] != ecosystem:
                continue
            hits = _corroborating_files(
                scan,
                patterns=rule.get("file_patterns", ()),
                suffixes=rule.get("file_suffixes", ()),
            )
            if hits:
                config_evidence.append(
                    f"{rule['evidence']} ({', '.join(hits[:5])}) — corroborates {entry['label']}"
                )

    # Every declared dependency, recognized as a framework signature or not,
    # deduped and flattened to name+version. Security-relevant libraries
    # (commons-collections, jsch, castor) are not frameworks and so never show
    # up under `frameworks` — this is what rule `requires_dependency`
    # conditions match against.
    declared: List[Dict[str, Any]] = []
    seen_declared = set()
    for dep in all_deps:
        key = (dep["name"], dep.get("version"))
        if key in seen_declared:
            continue
        seen_declared.add(key)
        if len(declared) >= _MAX_DECLARED_DEPENDENCIES:
            break
        declared.append({"name": dep["name"], "version": dep.get("version")})

    return {
        "manifests_parsed": parsed_manifests,
        "dependency_count": len(all_deps),
        "frameworks": frameworks,
        "declared_dependencies": declared,
        "declared_dependencies_truncated": len(seen_declared) > len(declared),
        "unrecognized_count": len(unrecognized),
        "unrecognized_sample": [f"{d['ecosystem']}:{d['name']}" for d in unrecognized[:20]],
        "unrecognized_dependencies": _unrecognized_list(unrecognized),
        "config_evidence": config_evidence,
    }
