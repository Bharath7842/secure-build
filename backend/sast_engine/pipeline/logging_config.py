"""What the repository's logging configuration does to a logged message (SAST-03-050).

Log forging (CWE-117) needs a layout that writes a line break through. Whether
one does is a fact about the configuration, not about the logging *library*:
SLF4J, Log4j and JUL syntax say nothing about encoding. This module finds the
configuration files in the repository, builds ``logger category -> appenders ->
layout`` for each, and says for every layout whether it neutralises CR/LF in

* the **message** (``%m`` / ``%msg``): ``neutralised`` when each occurrence is
  wrapped in ``%replace(..){'[\\r\\n]',..}`` / ``%enc{..}{CRLF}`` or the layout
  is JSON, ``raw`` when a bare ``%m`` is printed, ``unknown`` otherwise;
* the **throwable** (``%ex`` / ``%throwable`` / ``%xEx``): raw unless wrapped the
  same way or the layout is JSON. Logback and Log4j2 print a throwable even when
  the pattern has no converter for it, so a pattern without one is ``raw`` too —
  only ``%nopex`` switches it off.

Files read: ``logback[-spring|-<profile>].xml``, ``log4j2*.{xml,json,yaml,yml,
properties}``, ``log4j*.{xml,properties}``, ``logging.properties``. They are found
by a bounded walk of the repository because the scan's own file list drops
``log4j*.xml`` and most ``.properties``. Test resources are ignored.

When profiles disagree the answer is the least safe one. A configuration that
is not in the repository (a container-managed ``standalone.xml``) is simply
absent: the caller reports the layout as unknown, never as safe.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from xml.etree import ElementTree as ET

NEUTRALISED = "neutralised"
RAW = "raw"
UNKNOWN = "unknown"
_RANK = {NEUTRALISED: 0, UNKNOWN: 1, RAW: 2}

_CONFIG_NAME_RE = re.compile(
    r"^(?:logback(?:[-_.][\w.-]+)?\.xml|log4j2?(?:[-_.][\w.-]+)?\.(?:xml|json|jsn|ya?ml|properties)|logging\.properties)$",
    re.I,
)
_SKIP_DIRS = {".git", "node_modules", "target", "build", "dist", ".idea", ".gradle", "out", "venv", ".venv"}
_MAX_DEPTH = 10
_MAX_FILES = 40
_MAX_BYTES = 512 * 1024

_JSON_LAYOUT_RE = re.compile(r"json|logstash", re.I)
_MESSAGE_RE = re.compile(r"%(?:[-+]?\d+)?(?:\.-?\d+)?(?:m|msg|message)(?![A-Za-z])")
_THROWABLE_RE = re.compile(
    r"%(?:[-+]?\d+)?(?:\.-?\d+)?(?:ex|exception|throwable|xEx|xException|xThrowable|rEx|rootException|wEx|wex)(?![A-Za-z])"
)
_NOPEX_RE = re.compile(r"%(?:nopex|nopexception|nothrowable)\b")
# Wrappers that neutralise CR/LF over the converter they contain.
_ENC_WRAP_RE = re.compile(r"%(?:enc|encode)\{")
_REPLACE_WRAP_RE = re.compile(r"%replace[({]")


def worst(*values: str) -> str:
    return max(values, key=lambda v: _RANK[v]) if values else UNKNOWN


@dataclass(frozen=True)
class Layout:
    message_crlf: str = UNKNOWN
    throwable_crlf: str = UNKNOWN
    where: str = ""  # "path:line"


@dataclass
class Appender:
    name: str
    layout: Layout


@dataclass
class LoggerNode:
    name: str  # "" is the root
    appenders: List[str] = field(default_factory=list)
    additive: bool = True


@dataclass
class ConfigFile:
    path: str
    kind: str
    appenders: Dict[str, Appender] = field(default_factory=dict)
    loggers: List[LoggerNode] = field(default_factory=list)
    root: LoggerNode = field(default_factory=lambda: LoggerNode(""))


# --- pattern analysis -----------------------------------------------------------

def _wrapped_spans(pattern: str) -> List[Tuple[int, int, str]]:
    """(start, end, kind) of each CR/LF-neutralising wrapper in a pattern.

    ``%enc{%m}{CRLF}`` neutralises only when its second group names CRLF (the
    default encoding is HTML, which leaves a line break alone); ``%replace(%msg)
    {'[\\r\\n]','_'}`` / ``%replace{%m}{[\\r\\n]}{_}`` only when its regular
    expression matches a CR or LF."""
    spans: List[Tuple[int, int, str]] = []
    for m in list(_ENC_WRAP_RE.finditer(pattern)) + list(_REPLACE_WRAP_RE.finditer(pattern)):
        open_ch = pattern[m.end() - 1]
        close_ch = "}" if open_ch == "{" else ")"
        depth, i = 1, m.end()
        while i < len(pattern) and depth:
            if pattern[i] == open_ch:
                depth += 1
            elif pattern[i] == close_ch:
                depth -= 1
            i += 1
        second = re.match(r"\{([^}]*)\}", pattern[i:])
        if second is None:
            continue
        is_enc = m.group().startswith("%enc")
        if is_enc:
            ok = "CRLF" in second.group(1).upper()
        else:
            ok = re.search(r"\\[rnsR]|\\u000[aAdD]|\\x0[aAdD]|\[\^?\s*\]", second.group(1)) is not None
        if ok:
            spans.append((m.start(), i + second.end(), "enc" if is_enc else "replace"))
    return spans


def _converter_state(pattern: str, regex: "re.Pattern[str]") -> Optional[str]:
    """RAW / NEUTRALISED for every occurrence of a converter, None if absent."""
    spans = _wrapped_spans(pattern)
    found = False
    for m in regex.finditer(pattern):
        found = True
        if not any(s <= m.start() < e for s, e, _ in spans):
            return RAW
    return NEUTRALISED if found else None


def analyze_pattern(pattern: str, where: str = "") -> Layout:
    if not pattern or not pattern.strip():
        return Layout(UNKNOWN, UNKNOWN, where)
    message = _converter_state(pattern, _MESSAGE_RE) or UNKNOWN
    throwable = _converter_state(pattern, _THROWABLE_RE)
    if throwable is None:
        throwable = NEUTRALISED if _NOPEX_RE.search(pattern) else RAW  # printed by default
    return Layout(message, throwable, where)


def _json_layout(where: str) -> Layout:
    return Layout(NEUTRALISED, NEUTRALISED, where)


# --- file parsers -----------------------------------------------------------------

def _line_of(text: str, needle: str) -> int:
    index = text.find(needle) if needle else -1
    return text.count("\n", 0, index) + 1 if index >= 0 else 1


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _parse_logback(path: str, text: str, root: ET.Element) -> ConfigFile:
    cfg = ConfigFile(path, "logback")
    for ap in root.iter("appender"):
        name = ap.get("name") or ""
        layout = Layout(UNKNOWN, UNKNOWN, f"{path}:{_line_of(text, f'name=\"{name}\"')}")
        for child in ap.iter():
            tag = _local(child.tag)
            klass = child.get("class") or ""
            if tag in ("encoder", "layout") and _JSON_LAYOUT_RE.search(klass):
                layout = _json_layout(f"{path}:{_line_of(text, klass)}")
                break
            if tag == "pattern" and (child.text or "").strip():
                layout = analyze_pattern(child.text.strip(), f"{path}:{_line_of(text, child.text.strip()[:30])}")
                break
        cfg.appenders[name] = Appender(name, layout)
    for lg in root.iter("logger"):
        node = LoggerNode(lg.get("name") or "", [r.get("ref") or "" for r in lg.findall("appender-ref")],
                          (lg.get("additivity") or "true").lower() != "false")
        cfg.loggers.append(node)
    for r in root.iter("root"):
        cfg.root.appenders.extend(a.get("ref") or "" for a in r.findall("appender-ref"))
    return cfg


def _parse_log4j2_dict(path: str, text: str, data: dict, kind: str) -> ConfigFile:
    cfg = ConfigFile(path, kind)
    conf = data.get("Configuration") or data.get("configuration") or data

    def listify(v) -> list:
        return v if isinstance(v, list) else ([v] if v else [])

    appenders = conf.get("Appenders") or conf.get("appenders") or {}
    for atype, body in appenders.items():
        for ap in listify(body):
            if not isinstance(ap, dict):
                continue
            name = str(ap.get("name") or "")
            layout = Layout(UNKNOWN, UNKNOWN, f"{path}:{_line_of(text, name)}")
            for key, val in ap.items():
                if _JSON_LAYOUT_RE.search(key) and "Layout" in key:
                    layout = _json_layout(f"{path}:{_line_of(text, key)}")
                elif key == "PatternLayout":
                    pat = val.get("pattern") if isinstance(val, dict) else None
                    layout = analyze_pattern(str(pat or ""), f"{path}:{_line_of(text, str(pat or key)[:30])}")
            cfg.appenders[name] = Appender(name, layout)
    loggers = conf.get("Loggers") or conf.get("loggers") or {}
    for lg in listify(loggers.get("Logger") or loggers.get("logger")):
        refs = [str(r.get("ref")) for r in listify(lg.get("AppenderRef")) if isinstance(r, dict)]
        cfg.loggers.append(LoggerNode(str(lg.get("name") or ""), refs, str(lg.get("additivity", "true")).lower() != "false"))
    root = loggers.get("Root") or loggers.get("root")
    if isinstance(root, dict):
        cfg.root.appenders.extend(str(r.get("ref")) for r in listify(root.get("AppenderRef")) if isinstance(r, dict))
    return cfg


def _xml_to_dict(el: ET.Element) -> dict:
    """Log4j2 XML as the nested dict its JSON form uses (attributes as keys)."""
    out: dict = dict(el.attrib)
    for child in el:
        tag = _local(child.tag)
        value = _xml_to_dict(child)
        if tag == "Pattern" and (child.text or "").strip() and "pattern" not in out:
            out["pattern"] = child.text.strip()
        if tag in out:
            if not isinstance(out[tag], list):
                out[tag] = [out[tag]]
            out[tag].append(value)
        else:
            out[tag] = value
    return out


def _parse_log4j2_xml(path: str, text: str, root: ET.Element) -> ConfigFile:
    return _parse_log4j2_dict(path, text, {"Configuration": _xml_to_dict(root)}, "log4j2")


def _parse_log4j1_xml(path: str, text: str, root: ET.Element) -> ConfigFile:
    cfg = ConfigFile(path, "log4j1")
    for ap in root.iter("appender"):
        name = ap.get("name") or ""
        layout = Layout(UNKNOWN, UNKNOWN, f"{path}:{_line_of(text, f'name=\"{name}\"')}")
        for lay in ap.iter("layout"):
            for param in lay.iter("param"):
                if (param.get("name") or "") == "ConversionPattern":
                    layout = analyze_pattern(param.get("value") or "", f"{path}:{_line_of(text, param.get('value') or '')}")
        cfg.appenders[name] = Appender(name, layout)
    for lg in list(root.iter("logger")) + list(root.iter("category")):
        cfg.loggers.append(LoggerNode(lg.get("name") or "", [r.get("ref") or "" for r in lg.findall("appender-ref")],
                                      (lg.get("additivity") or "true").lower() != "false"))
    for r in root.iter("root"):
        cfg.root.appenders.extend(a.get("ref") or "" for a in r.findall("appender-ref"))
    return cfg


def _props(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    logical = re.sub(r"\\\r?\n\s*", "", text)
    for raw in logical.splitlines():
        line = raw.strip()
        if not line or line[0] in "#!":
            continue
        m = re.match(r"([^=:\s]+)\s*[=:]\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def _parse_log4j1_props(path: str, text: str, props: Dict[str, str]) -> ConfigFile:
    cfg = ConfigFile(path, "log4j1")
    for key, value in props.items():
        m = re.match(r"log4j\.appender\.(\w[\w.-]*)\.layout\.ConversionPattern$", key)
        if m:
            cfg.appenders[m.group(1)] = Appender(m.group(1), analyze_pattern(value, f"{path}:{_line_of(text, value[:30])}"))
    for key, value in props.items():
        m = re.match(r"log4j\.appender\.(\w[\w.-]*)\.layout$", key)
        if m and m.group(1) not in cfg.appenders:
            cfg.appenders[m.group(1)] = Appender(m.group(1), Layout(UNKNOWN, UNKNOWN, f"{path}:{_line_of(text, key)}"))
    for key, value in props.items():
        parts = [p.strip() for p in value.split(",")]
        if key in ("log4j.rootLogger", "log4j.rootCategory"):
            cfg.root.appenders.extend(parts[1:])
        elif key.startswith(("log4j.logger.", "log4j.category.")):
            name = key.split(".", 2)[2]
            add = props.get(f"log4j.additivity.{name}", "true").lower() != "false"
            cfg.loggers.append(LoggerNode(name, parts[1:], add))
    return cfg


def _parse_log4j2_props(path: str, text: str, props: Dict[str, str]) -> ConfigFile:
    cfg = ConfigFile(path, "log4j2")
    appender_ids = {k.split(".")[1] for k in props if k.startswith("appender.") and k.count(".") >= 2}
    names: Dict[str, str] = {}
    for aid in appender_ids:
        name = props.get(f"appender.{aid}.name", aid)
        names[aid] = name
        ltype = props.get(f"appender.{aid}.layout.type", "")
        if _JSON_LAYOUT_RE.search(ltype):
            layout = _json_layout(f"{path}:{_line_of(text, f'appender.{aid}.layout.type')}")
        else:
            pat = props.get(f"appender.{aid}.layout.pattern", "")
            layout = analyze_pattern(pat, f"{path}:{_line_of(text, pat[:30])}") if ltype.lower() in ("patternlayout", "") and pat \
                else Layout(UNKNOWN, UNKNOWN, f"{path}:{_line_of(text, f'appender.{aid}.')}")
        cfg.appenders[name] = Appender(name, layout)
    ids = {k.split(".")[1] for k in props if k.startswith("logger.") and k.count(".") >= 2}
    for lid in ids:
        refs = [v for k, v in props.items() if k.startswith(f"logger.{lid}.appenderRef.") and k.endswith(".ref")]
        cfg.loggers.append(LoggerNode(props.get(f"logger.{lid}.name", lid), refs,
                                      props.get(f"logger.{lid}.additivity", "true").lower() != "false"))
    cfg.root.appenders.extend(v for k, v in props.items() if k.startswith("rootLogger.appenderRef.") and k.endswith(".ref"))
    return cfg


def _parse_jul(path: str, text: str, props: Dict[str, str]) -> ConfigFile:
    cfg = ConfigFile(path, "jul")

    def layout_for(handler: str) -> Layout:
        fmt = props.get(f"{handler}.formatter", "")
        where = f"{path}:{_line_of(text, handler)}"
        if fmt.endswith("SimpleFormatter"):
            return Layout(RAW, RAW, where)  # prints the message and the stack trace verbatim
        return Layout(UNKNOWN, UNKNOWN, where)

    def handlers(prefix: str) -> List[str]:
        return [h.strip() for h in props.get(f"{prefix}handlers".lstrip("."), "").replace(",", " ").split() if h.strip()]

    for h in set(handlers("") + [h for k, v in props.items() if k.endswith(".handlers") for h in v.replace(",", " ").split()]):
        cfg.appenders[h] = Appender(h, layout_for(h))
    cfg.root.appenders.extend(handlers(""))
    for key, value in props.items():
        if key.endswith(".handlers") and key != "handlers":
            name = key[: -len(".handlers")]
            cfg.loggers.append(LoggerNode(name, value.replace(",", " ").split(),
                                          props.get(f"{name}.useParentHandlers", "true").lower() != "false"))
    return cfg


def parse_file(path: str, text: str) -> Optional[ConfigFile]:
    lower = os.path.basename(path).lower()
    try:
        if lower.endswith(".xml"):
            if "<!ENTITY" in text:  # an entity-declaring file from a scanned repo is not parsed
                return None
            root = ET.fromstring(text)
            tag = _local(root.tag).lower()
            if lower.startswith("logback") or tag == "configuration" and root.find(".//appender") is not None and "log4j2" not in lower:
                if tag == "configuration" and lower.startswith("logback"):
                    return _parse_logback(path, text, root)
            if tag == "configuration" and (lower.startswith("log4j2") or root.find("Appenders") is not None):
                return _parse_log4j2_xml(path, text, root)
            if tag == "configuration" and root.find(".//appender") is not None:
                return _parse_logback(path, text, root) if lower.startswith("logback") else _parse_log4j1_xml(path, text, root)
            if tag == "configuration":  # log4j:configuration
                return _parse_log4j1_xml(path, text, root)
            return None
        if lower.endswith((".json", ".jsn")):
            return _parse_log4j2_dict(path, text, json.loads(text), "log4j2")
        if lower.endswith((".yaml", ".yml")):
            import yaml  # already a runtime dependency of the corpus and CLI; optional here

            return _parse_log4j2_dict(path, text, yaml.safe_load(text) or {}, "log4j2")
        if lower.endswith(".properties"):
            props = _props(text)
            if lower == "logging.properties":
                return _parse_jul(path, text, props)
            if lower.startswith("log4j2") or any(k.startswith(("appender.", "rootLogger.")) for k in props):
                return _parse_log4j2_props(path, text, props)
            return _parse_log4j1_props(path, text, props)
    except Exception:  # noqa: BLE001 - an unparseable file is simply not evidence
        return None
    return None


# --- the set of configuration files ----------------------------------------------

@dataclass
class Resolution:
    """What a category's records go through."""
    layouts: List[Tuple[str, Appender]]  # (config file path, appender)
    unresolved: List[str]  # appender names referenced but not defined
    files: int

    def part(self, which: str) -> str:
        values = [getattr(a.layout, which) for _, a in self.layouts]
        if self.unresolved:
            values.append(UNKNOWN)
        return worst(*values) if values else UNKNOWN


@dataclass
class LoggingConfig:
    files: List[ConfigFile] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return bool(self.files)

    def resolve(self, category: Optional[str]) -> Resolution:
        layouts: List[Tuple[str, Appender]] = []
        unresolved: List[str] = []
        for cfg in self.files:
            if category is None:
                refs = {r for lg in cfg.loggers for r in lg.appenders} | set(cfg.root.appenders)
            else:
                refs = self._refs(cfg, category)
            for ref in sorted(refs):
                appender = cfg.appenders.get(ref)
                if appender is None:
                    unresolved.append(f"{ref} ({cfg.path})")
                else:
                    layouts.append((cfg.path, appender))
        return Resolution(layouts, unresolved, len(self.files))

    @staticmethod
    def _refs(cfg: ConfigFile, category: str) -> set:
        matching = sorted(
            (lg for lg in cfg.loggers if lg.name and (category == lg.name or category.startswith(lg.name + "."))),
            key=lambda lg: len(lg.name), reverse=True,
        )
        refs: set = set()
        reaches_root = True
        for lg in matching:
            refs.update(lg.appenders)
            if not lg.additive:
                reaches_root = False
                break
        if reaches_root:
            refs.update(cfg.root.appenders)
        return refs

    def summary(self) -> str:
        if not self.files:
            return "no logging configuration found in the repository"
        return "; ".join(f"{f.kind} {f.path} ({len(f.appenders)} appender(s))" for f in self.files)


def _is_test_path(rel: str) -> bool:
    parts = [p.lower() for p in re.split(r"[\\/]", rel)]
    return "test" in parts or "tests" in parts or "__tests__" in parts


def find_config_paths(repo_root: Path) -> List[str]:
    found: List[str] = []
    root = str(repo_root)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath[len(root):].count(os.sep)
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")] if depth < _MAX_DEPTH else []
        for name in filenames:
            if _CONFIG_NAME_RE.match(name):
                rel = os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")
                if not _is_test_path(rel):
                    found.append(rel)
    return sorted(found)[:_MAX_FILES]


def load(repo_root: Optional[Path]) -> LoggingConfig:
    cfg = LoggingConfig()
    if repo_root is None:
        return cfg
    root = Path(repo_root)
    for rel in find_config_paths(root):
        try:
            full = root / rel
            if full.stat().st_size > _MAX_BYTES:
                cfg.skipped.append(rel)
                continue
            parsed = parse_file(rel, full.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if parsed is None:
            cfg.skipped.append(rel)
        else:
            cfg.files.append(parsed)
    return cfg
