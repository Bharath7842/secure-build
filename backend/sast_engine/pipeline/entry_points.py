"""entry_points.py — Java entry points registered by deployment descriptors (SAST-02-070).

An annotation is not the only way code gets called. A servlet listed in
`web.xml`, a session bean or message-driven bean in `ejb-jar.xml`, a web
service endpoint in `webservices.xml` / `sun-jaxws.xml`, a Spring XML `<bean>`
and a JSF managed bean are all invoked by the container with no reference
anywhere in the Java code. Before "no callers" can be claimed, these must be
known; `call_graph` adds them to its entry points.

`parse_descriptor(path, text)` returns what one descriptor registers:

* `classes` — FQNs the container instantiates and calls (servlets, filters,
  listeners, beans, endpoints), each with the descriptor kind as its source;
* `methods` — specific (FQN, method name) pairs a descriptor names
  (`init-method`, `destroy-method`);
* `interfaces` — EJB business interfaces mapped to their bean class
  (`<remote>`/`<local>`/`<business-local>`/`<business-remote>` -> `<ejb-class>`),
  so a call through the interface resolves to the bean even when the bean
  class does not `implements` it (EJB 2.x).

Pure (text in, facts out) and best-effort: a descriptor that does not parse
registers nothing — and `call_graph` then cannot prove a method unreferenced.
Repository XML is untrusted: parsed with `defusedxml` when installed (a
descriptor declaring entities is then a parse failure), else the stdlib parser,
whose expat neither fetches external entities nor expands them without bound.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Set, Tuple
from xml.etree.ElementTree import Element

try:
    from defusedxml import ElementTree as ET
except ImportError:  # pragma: no cover - defusedxml is optional
    from xml.etree import ElementTree as ET  # noqa: S405

DESCRIPTOR_NAMES = frozenset({
    "web.xml", "web-fragment.xml", "ejb-jar.xml", "webservices.xml", "sun-jaxws.xml", "faces-config.xml",
})
MAX_DESCRIPTOR_BYTES = 2_000_000

_CLASS_TAGS = {
    "servlet-class": "web.xml", "filter-class": "web.xml", "listener-class": "web.xml",
    "ejb-class": "ejb-jar.xml", "managed-bean-class": "faces-config.xml",
    "service-endpoint-interface": "webservices.xml",
}
_BUSINESS_TAGS = ("remote", "local", "business-local", "business-remote", "home", "local-home")


@dataclass
class DescriptorEntries:
    classes: Dict[str, str] = field(default_factory=dict)  # fqcn -> source
    methods: Set[Tuple[str, str]] = field(default_factory=set)  # (fqcn, method)
    interfaces: Dict[str, Set[str]] = field(default_factory=dict)  # interface fqcn -> bean classes
    failed: List[str] = field(default_factory=list)  # descriptors that did not parse

    def merge(self, other: "DescriptorEntries") -> None:
        for fqcn, source in other.classes.items():
            self.classes.setdefault(fqcn, source)
        self.methods |= other.methods
        for iface, beans in other.interfaces.items():
            self.interfaces.setdefault(iface, set()).update(beans)
        self.failed.extend(other.failed)


def is_descriptor(path: str) -> bool:
    """Is `path` a descriptor this module reads? Spring XML has no fixed name,
    so any other `.xml` is a candidate and is kept only if its root is `<beans>`."""
    return path.lower().endswith(".xml")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _text(node: Element) -> str:
    return (node.text or "").strip()


def parse_descriptor(path: str, text: str) -> DescriptorEntries:
    out = DescriptorEntries()
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    if len(text) > MAX_DESCRIPTOR_BYTES:
        return out
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError):  # defusedxml raises ValueError subclasses
        if name in DESCRIPTOR_NAMES:
            out.failed.append(path)
        return out
    root_tag = _local(root.tag)
    if root_tag == "beans":
        _spring_beans(root, out)
        return out
    if name not in DESCRIPTOR_NAMES and root_tag not in ("web-app", "ejb-jar", "webservices", "endpoints",
                                                          "faces-config"):
        return out
    for node in root.iter():
        tag = _local(node.tag)
        if tag in _CLASS_TAGS and _text(node):
            out.classes.setdefault(_text(node), _CLASS_TAGS[tag])
        elif tag == "endpoint" and node.get("implementation"):  # sun-jaxws.xml
            out.classes.setdefault(node.get("implementation").strip(), "sun-jaxws.xml")
        elif tag in ("session", "message-driven", "entity"):
            _ejb(node, out)
    return out


def _ejb(bean: Element, out: DescriptorEntries) -> None:
    children = {_local(c.tag): _text(c) for c in bean}
    ejb_class = children.get("ejb-class")
    if not ejb_class:
        return
    for c in bean:
        if _local(c.tag) in _BUSINESS_TAGS and _text(c):
            out.interfaces.setdefault(_text(c), set()).add(ejb_class)
            out.classes.setdefault(_text(c), "ejb-jar.xml")


def _spring_beans(root: Element, out: DescriptorEntries) -> None:
    for node in root.iter():
        if _local(node.tag) != "bean":
            continue
        fqcn = (node.get("class") or "").strip()
        if not fqcn:
            continue
        out.classes.setdefault(fqcn, "spring.xml")
        for attr in ("init-method", "destroy-method", "factory-method"):
            method = (node.get(attr) or "").strip()
            if method:
                out.methods.add((fqcn, method))


def parse_descriptors(texts: Dict[str, Optional[str]]) -> DescriptorEntries:
    """Every descriptor among `texts` (path -> file text; None when unreadable)."""
    out = DescriptorEntries()
    for path, text in sorted(texts.items()):
        if text is None:
            if PurePosixPath(path).name.lower() in DESCRIPTOR_NAMES:
                out.failed.append(path)
            continue
        out.merge(parse_descriptor(path, text))
    return out
