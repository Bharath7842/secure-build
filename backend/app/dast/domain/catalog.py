"""Check schema, validation and rule packs (DAST-03-010 .. -030): pure, no file or YAML I/O.

The loader (`app/services/dast_catalog.py`) reads YAML and hands plain mappings here; this
module decides whether they are valid checks. Problems are returned as `CatalogIssue`s that
name the check and the item index, and the loader adds file and line.

A check never carries a payload. Two guards enforce that: any field outside the schema is an
error (so `payload:` cannot sneak in as an unknown field), and a short list of payload-ish
field names gets a specific message saying why.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable, Mapping, Sequence

from .detectors import PASSIVE_SIGNALS
from .entities import Check, CheckMode, Location, Severity

CHECK_ID_PREFIX = "dast-"
STANDARD_KEYS = ("owasp", "apisec", "wstg", "cwe")
DEPENDENCIES = ("second_identity", "oast", "schema")
MISSING_ACTIONS = ("skip", "degrade", "assist-only")
APPLIES_TO_KEYS = frozenset({"locations", "param_types", "methods", "content_types", "path_patterns", "needs_object_id"})

# `Location.QUERY|PATH|HEADER|BODY` are injection points; RESPONSE is for passive checks that
# only read what was already observed.
_LOCATIONS = {loc.value for loc in Location}

CHECK_FIELDS = frozenset(
    {
        "id", "title", "description", "owasp", "apisec", "wstg", "cwe", "applies_to", "location", "signal",
        "severity", "mode", "remediation_ref", "dependencies", "passive", "load_generating", "enabled",
        "degraded_note", "aliases",
    }
)
REQUIRED_FIELDS = ("id", "title", "location", "severity", "mode", "remediation_ref")

# Names that suggest a fixed payload. Rejected with a pointed message rather than a generic
# "unknown field" so a rule author learns why.
PAYLOAD_FIELDS = frozenset(
    {"payload", "payloads", "request", "requests", "body", "value", "values", "inputs", "input", "fuzz",
     "wordlist", "raw", "data", "exploit", "attack", "vector", "vectors", "canary", "template"}
)


@dataclass(frozen=True)
class CatalogIssue:
    message: str
    index: int  # position of the check in its source list
    check_id: str = ""
    fatal: bool = True  # False: the check loaded, but was changed (e.g. downgraded to assist-only)

    def __str__(self) -> str:
        who = f" ({self.check_id})" if self.check_id else ""
        return f"item {self.index}{who}: {self.message}"


@dataclass(frozen=True)
class ParseResult:
    checks: tuple[Check, ...]
    issues: tuple[CatalogIssue, ...]

    @property
    def errors(self) -> tuple[CatalogIssue, ...]:
        return tuple(i for i in self.issues if i.fatal)

    @property
    def notes(self) -> tuple[CatalogIssue, ...]:
        return tuple(i for i in self.issues if not i.fatal)


def _as_list(value: Any) -> list[Any] | None:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return None


def _enum(enum_cls: type, raw: Any, field: str, errors: list[str]):
    try:
        return enum_cls(str(raw).strip().lower() if enum_cls is not Severity else str(raw).strip().upper())
    except ValueError:
        allowed = ", ".join(e.value for e in enum_cls)  # type: ignore[attr-defined]
        errors.append(f"{field} {raw!r} is not one of: {allowed}")
        return None


def parse_check(
    raw: Mapping[str, Any],
    index: int,
    *,
    signal_names: frozenset[str],
    remediation_exists: Callable[[str], bool],
    source: str = "catalog",
    version: int = 1,
    strict_signals: bool = False,
    default_remediation_ref: str = "",
) -> tuple[Check | None, list[CatalogIssue]]:
    """Validate one raw mapping. Returns the check (None if any fatal error) and its issues.

    `strict_signals` (custom rules): naming a signal that does not exist is an error, since it
    is almost certainly a typo. Naming none at all is still allowed and downgrades the check to
    assist-only. For the shipped catalog an unknown name is dropped and flagged instead.
    `default_remediation_ref` fills a missing `remediation_ref` (custom rules)."""
    if not isinstance(raw, Mapping):
        return None, [CatalogIssue("a check must be a mapping", index)]
    check_id = str(raw.get("id") or "").strip()
    errors: list[str] = []
    notes: list[str] = []

    for name in raw:
        if name in PAYLOAD_FIELDS:
            errors.append(f"field {name!r} is not allowed: checks must not carry fixed payload strings (the model constructs inputs at scan time)")
        elif name not in CHECK_FIELDS:
            errors.append(f"unknown field {name!r}")
    for name in REQUIRED_FIELDS:
        if raw.get(name) in (None, "") and not (name == "remediation_ref" and default_remediation_ref):
            errors.append(f"missing required field {name!r}")

    if check_id and not check_id.startswith(CHECK_ID_PREFIX):
        errors.append(f"id must start with {CHECK_ID_PREFIX!r}")
    if check_id and not all(c.isalnum() or c in "-_" for c in check_id):
        errors.append("id may contain only letters, digits, '-' and '_'")

    standards: dict[str, tuple[str, ...]] = {}
    for key in STANDARD_KEYS:
        values = _as_list(raw.get(key))
        if values is None or not all(isinstance(v, str) and v.strip() for v in values):
            errors.append(f"{key} must be a list of non-empty strings")
            continue
        standards[key] = tuple(v.strip() for v in values)
    if not any(standards.values()):
        errors.append("at least one standard tag (owasp, apisec, wstg or cwe) is required")

    location = _enum(Location, raw.get("location"), "location", errors) if raw.get("location") else None
    severity = _enum(Severity, raw.get("severity"), "severity", errors) if raw.get("severity") else None
    mode = _enum(CheckMode, raw.get("mode"), "mode", errors) if raw.get("mode") else None

    applies_to = raw.get("applies_to") or {}
    if not isinstance(applies_to, Mapping):
        errors.append("applies_to must be a mapping")
        applies_to = {}
    else:
        for key in applies_to:
            if key not in APPLIES_TO_KEYS:
                errors.append(f"applies_to has unknown key {key!r}")
        for loc in applies_to.get("locations") or []:
            if str(loc) not in _LOCATIONS:
                errors.append(f"applies_to.locations {loc!r} is not a valid location")

    dependencies = raw.get("dependencies") or {}
    on_missing: dict[str, str] = {}
    if isinstance(dependencies, Mapping):
        for dep, action in dependencies.items():
            if dep not in DEPENDENCIES:
                errors.append(f"dependencies has unknown dependency {dep!r} (expected one of: {', '.join(DEPENDENCIES)})")
            elif action not in MISSING_ACTIONS:
                errors.append(f"dependencies.{dep} must be one of: {', '.join(MISSING_ACTIONS)}")
            else:
                on_missing[dep] = action
    else:
        errors.append("dependencies must be a mapping of dependency name to skip|degrade|assist-only")

    remediation_ref = str(raw.get("remediation_ref") or "").strip() or default_remediation_ref
    if remediation_ref and not remediation_exists(remediation_ref):
        errors.append(f"remediation_ref {remediation_ref!r} does not resolve to an existing remediation file")

    signal_list = _as_list(raw.get("signal"))
    if signal_list is None or not all(isinstance(s, str) for s in signal_list):
        errors.append("signal must be a list of detector signal names")
        signal_list = []
    known = tuple(s for s in signal_list if s in signal_names)
    unknown = tuple(s for s in signal_list if s not in signal_names)
    flags: list[str] = []
    if unknown and strict_signals:
        errors.append(f"unknown detector signal(s): {', '.join(unknown)}")
    elif unknown:
        flags.append("unknown_signal")
        notes.append(f"unknown detector signal(s) {', '.join(unknown)} ignored")

    passive = bool(raw.get("passive", False))
    if passive:
        active = [s for s in known if s not in PASSIVE_SIGNALS]
        if active:
            errors.append(f"passive check names active signal(s): {', '.join(active)}")

    aliases = _as_list(raw.get("aliases"))
    if aliases is None or not all(isinstance(a, str) for a in aliases):
        errors.append("aliases must be a list of ids")
        aliases = []

    if errors:
        return None, [CatalogIssue(message, index, check_id) for message in errors]

    assert location is not None and severity is not None and mode is not None
    if not known and mode is not CheckMode.ASSIST_ONLY:
        mode = CheckMode.ASSIST_ONLY
        flags.append("no_resolvable_signal")
        notes.append("names no detector signal that exists, so it can only surface as assist-only")
    elif not known:
        flags.append("no_resolvable_signal")

    enabled = raw.get("enabled", True)
    load_generating = bool(raw.get("load_generating", False))
    check = Check(
        check_id=check_id,
        title=str(raw["title"]).strip(),
        standards=standards,
        location=location,
        detector_signals=known,
        base_severity=severity,
        mode=mode,
        remediation_ref=remediation_ref,
        requires=tuple(on_missing),
        applies_to=dict(applies_to),
        description=str(raw.get("description") or "").strip(),
        passive=passive,
        load_generating=load_generating,
        enabled_by_default=bool(enabled) and not load_generating and mode is not CheckMode.OPT_IN,
        on_missing=on_missing,
        degraded_note=str(raw.get("degraded_note") or "").strip(),
        aliases=tuple(a.strip() for a in aliases if a.strip()),
        flags=tuple(flags),
        source=source,
        version=version,
    )
    return check, [CatalogIssue(note, index, check_id, fatal=False) for note in notes]


def parse_checks(
    items: Sequence[Any],
    *,
    signal_names: frozenset[str],
    remediation_exists: Callable[[str], bool],
    source: str = "catalog",
) -> ParseResult:
    """Validate a list of raw checks together: per-check rules plus duplicate ids/aliases."""
    checks: list[Check] = []
    issues: list[CatalogIssue] = []
    seen_ids: dict[str, int] = {}
    for index, raw in enumerate(items):
        check, found = parse_check(
            raw, index, signal_names=signal_names, remediation_exists=remediation_exists, source=source
        )
        issues.extend(found)
        if check is None:
            continue
        if check.check_id in seen_ids:
            issues.append(CatalogIssue(f"duplicate id (first defined at item {seen_ids[check.check_id]})", index, check.check_id))
            continue
        seen_ids[check.check_id] = index
        checks.append(check)
    taken = set(seen_ids)
    final: list[Check] = []
    for check in checks:
        clash = [a for a in check.aliases if a in taken and a != check.check_id]
        if clash:
            issues.append(CatalogIssue(f"alias {clash[0]!r} collides with another check id", seen_ids[check.check_id], check.check_id))
            continue
        final.append(check)
    return ParseResult(tuple(final), tuple(issues))


# ---- packs ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PackDef:
    """A rule pack: a *selection* over the catalog, never a copy of checks."""

    pack_id: str
    title: str
    description: str = ""
    enabled_by_default: bool = False
    ids: tuple[str, ...] = ()  # explicit check ids (aliases accepted)
    tags: Mapping[str, tuple[str, ...]] = None  # type: ignore[assignment]  # standard key -> values, or ("*",)
    passive: bool | None = None  # True: every passive check

    def __post_init__(self) -> None:
        if self.tags is None:
            object.__setattr__(self, "tags", {})


def parse_packs(items: Sequence[Any], known_check_ids: Iterable[str]) -> tuple[tuple[PackDef, ...], list[str]]:
    """Validate pack definitions. Returns (packs, error messages)."""
    known = set(known_check_ids)
    packs: list[PackDef] = []
    errors: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(items):
        if not isinstance(raw, Mapping) or not raw.get("id"):
            errors.append(f"pack {index}: needs an id")
            continue
        pack_id = str(raw["id"]).strip()
        unknown_fields = set(raw) - {"id", "title", "description", "enabled_by_default", "select"}
        if unknown_fields:
            errors.append(f"pack {pack_id}: unknown field(s) {', '.join(sorted(unknown_fields))}")
            continue
        if pack_id in seen:
            errors.append(f"pack {pack_id}: duplicate pack id")
            continue
        seen.add(pack_id)
        select = raw.get("select") or {}
        if not isinstance(select, Mapping) or set(select) - {"ids", "tags", "passive"} or not select:
            errors.append(f"pack {pack_id}: select must be a mapping with ids, tags and/or passive")
            continue
        ids = tuple(str(i) for i in select.get("ids") or ())
        missing = [i for i in ids if i not in known]
        if missing:
            errors.append(f"pack {pack_id}: select.ids names unknown check(s): {', '.join(missing)}")
            continue
        raw_tags = select.get("tags") or {}
        bad_keys = [k for k in raw_tags if k not in STANDARD_KEYS]
        if bad_keys:
            errors.append(f"pack {pack_id}: select.tags has unknown standard(s): {', '.join(bad_keys)}")
            continue
        tags = {k: tuple(str(v) for v in (vals if isinstance(vals, (list, tuple)) else [vals])) for k, vals in raw_tags.items()}
        packs.append(
            PackDef(
                pack_id=pack_id,
                title=str(raw.get("title") or pack_id),
                description=str(raw.get("description") or ""),
                enabled_by_default=bool(raw.get("enabled_by_default", False)),
                ids=ids,
                tags=tags,
                passive=select.get("passive"),
            )
        )
    return tuple(packs), errors


def _matches_tags(check: Check, tags: Mapping[str, Sequence[str]]) -> bool:
    for key, wanted in tags.items():
        have = check.standards.get(key, ())
        if "*" in wanted:
            if have:
                return True
        elif any(any(h == w or h.startswith(w) for h in have) for w in wanted):
            return True
    return False


def pack_check_ids(pack: PackDef, checks: Sequence[Check]) -> list[str]:
    """Ids of the checks `pack` selects, in catalog order, each once."""
    by_alias = {a: c.check_id for c in checks for a in c.aliases}
    explicit = {by_alias.get(i, i) for i in pack.ids}
    out: list[str] = []
    for check in checks:
        selected = (
            check.check_id in explicit
            or (bool(pack.tags) and _matches_tags(check, pack.tags))
            or (pack.passive is True and check.passive)
        )
        if pack.passive is True and not pack.ids and not pack.tags:
            selected = check.passive
        if selected and check.check_id not in out:
            out.append(check.check_id)
    return out


@dataclass(frozen=True)
class Catalog:
    """A validated catalog: checks and packs. Immutable; build a new one to change anything."""

    checks: tuple[Check, ...]
    packs: tuple[PackDef, ...]
    issues: tuple[CatalogIssue, ...] = ()

    def get(self, check_id: str) -> Check | None:
        return self._by_id().get(self.resolve_id(check_id))

    def resolve_id(self, check_id: str) -> str:
        """Canonical id for `check_id`, following aliases; unknown ids come back unchanged."""
        for check in self.checks:
            if check.check_id == check_id or check_id in check.aliases:
                return check.check_id
        return check_id

    def _by_id(self) -> dict[str, Check]:
        return {c.check_id: c for c in self.checks}

    def pack(self, pack_id: str) -> PackDef | None:
        return next((p for p in self.packs if p.pack_id == pack_id), None)

    def pack_checks(self, pack_id: str) -> list[Check]:
        pack = self.pack(pack_id)
        if pack is None:
            return []
        ids = pack_check_ids(pack, self.checks)
        by_id = self._by_id()
        return [by_id[i] for i in ids]

    def with_checks(self, extra: Sequence[Check]) -> "Catalog":
        """This catalog plus `extra` checks (custom rules). Ids already present are kept as-is."""
        have = {c.check_id for c in self.checks}
        return replace(self, checks=self.checks + tuple(c for c in extra if c.check_id not in have))


def standards_for(check: Check) -> list[str]:
    """Every standard the check is tagged with, as the labels findings carry:
    `["OWASP A03:2021", "OWASP API8:2023", "WSTG-INPV-05", "CWE-89"]`. A finding reports
    against all of them."""
    labels: list[str] = []
    for key in STANDARD_KEYS:
        for tag in check.standards.get(key, ()):
            labels.append(f"OWASP {tag}" if key in ("owasp", "apisec") else tag)
    return labels


def check_to_dict(check: Check) -> dict[str, Any]:
    """JSON-safe form of a check (API responses and scan snapshots)."""
    return {
        "id": check.check_id,
        "title": check.title,
        "description": check.description,
        "standards": {k: list(v) for k, v in check.standards.items()},
        "location": check.location.value,
        "signals": list(check.detector_signals),
        "severity": check.base_severity.value,
        "mode": check.mode.value,
        "remediation_ref": check.remediation_ref,
        "dependencies": dict(check.on_missing),
        "degraded_note": check.degraded_note,
        "applies_to": dict(check.applies_to),
        "passive": check.passive,
        "load_generating": check.load_generating,
        "enabled_by_default": check.enabled_by_default,
        "aliases": list(check.aliases),
        "flags": list(check.flags),
        "source": check.source,
        "version": check.version,
    }


def check_from_dict(data: Mapping[str, Any]) -> Check:
    """Inverse of `check_to_dict`, for reading a stored snapshot back. Does not validate:
    a snapshot is trusted history, not new input."""
    return Check(
        check_id=data["id"],
        title=data["title"],
        standards={k: tuple(v) for k, v in (data.get("standards") or {}).items()},
        location=Location(data["location"]),
        detector_signals=tuple(data.get("signals") or ()),
        base_severity=Severity(data["severity"]),
        mode=CheckMode(data["mode"]),
        remediation_ref=data.get("remediation_ref") or "",
        requires=tuple((data.get("dependencies") or {}).keys()),
        applies_to=dict(data.get("applies_to") or {}),
        description=data.get("description") or "",
        passive=bool(data.get("passive")),
        load_generating=bool(data.get("load_generating")),
        enabled_by_default=bool(data.get("enabled_by_default", True)),
        on_missing=dict(data.get("dependencies") or {}),
        degraded_note=data.get("degraded_note") or "",
        aliases=tuple(data.get("aliases") or ()),
        flags=tuple(data.get("flags") or ()),
        source=data.get("source") or "catalog",
        version=int(data.get("version") or 1),
    )
