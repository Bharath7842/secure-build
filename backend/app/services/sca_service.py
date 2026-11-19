"""SCA vulnerability analysis via OSV.dev (with NVD CVSS enrichment).

Replaces the former purl-batch approach with a version-agnostic per-package
query so that NOT_AFFECTED_BY_VERSION is observable, full CVSS v3/v4 scoring
is computed locally (no heuristic), and NVD fills in missing scores for CVE-
identified findings.

All logic is self-contained in this module — no dependency on the SCA_VEX_App
sub-project (which will be deleted).  The only runtime dependency added is
httpx, which is already in requirements.txt.

Public API (unchanged call-site contract):
    run_sca(components: list[dict]) -> dict
        components: CycloneDX-style dicts with at least {purl, name, version,
                    group (optional), ecosystem (optional)}

Returns the same shape as before:
    {
        "vulnerabilities": [...],   # one entry per component with vulns
        "vex_statements": [...],
        "component_count": int,
        "vulnerable_component_count": int,
    }

Each vuln dict inside "vulnerabilities" is now richer:
    {
        "id": str,            # CVE-id preferred over GHSA-id
        "aliases": list[str],
        "summary": str,       # normalized, markdown-stripped description
        "severity": str,      # from CVSS score, never heuristic fallback
        "cvss_score": float | None,
        "cvss_vector": str,
        "cwe_ids": list[str],
        "details": str,       # same as summary (kept for compat)
        "references": list[str],
        "published": str,
        "modified": str,
        "match_status": str,  # "vulnerable" | "not_affected_by_version" | "not_evaluable"
        "fixed_versions": list[str],
        "affected_versions": list[str],
    }
"""

from __future__ import annotations

import logging
import math
import os
import re
import threading
import time
from collections import defaultdict
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

logger = logging.getLogger("sca.service")

# ---------------------------------------------------------------------------
# Match statuses
# ---------------------------------------------------------------------------
MATCH_VULNERABLE = "vulnerable"
MATCH_NOT_AFFECTED_BY_VERSION = "not_affected_by_version"
MATCH_NOT_EVALUABLE = "not_evaluable"

# ---------------------------------------------------------------------------
# OSV query constants
# ---------------------------------------------------------------------------
_OSV_BASE = "https://api.osv.dev/v1"
_OSV_MAX_PAGES = 10
_OSV_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_OSV_HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

_MAVEN_ECOSYSTEMS = frozenset({"maven", "gradle", "kotlin", "sbt", "scala", "clojure"})

_OSV_ECOSYSTEM_MAP = {
    "npm": "npm", "deno": "npm",
    "maven": "Maven", "gradle": "Maven", "kotlin": "Maven",
    "sbt": "Maven", "scala": "Maven", "clojure": "Maven",
    "pypi": "PyPI", "python": "PyPI",
    "golang": "Go", "go": "Go",
    "cargo": "crates.io", "rust": "crates.io",
    "ruby": "RubyGems", "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist", "php": "Packagist",
    "dart": "Pub", "pub": "Pub",
    "r": "CRAN", "cran": "CRAN",
    "haskell": "Hackage", "hackage": "Hackage",
    "hex": "Hex", "elixir": "Hex",
}

# ---------------------------------------------------------------------------
# NVD enrichment constants
# ---------------------------------------------------------------------------
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_NVD_HEADERS = {"Accept": "application/json"}
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_NVD_METRIC_BLOCKS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_MAX_CVSS_ENRICH_LOOKUPS = 100

# ---------------------------------------------------------------------------
# Description normalization
# ---------------------------------------------------------------------------
_MAX_DESCRIPTION = 4000
_MAX_REFERENCES = 20
_MAX_AFFECTED_VERSIONS = 200
_MAX_RANGES = 20

_HEADING_RE = re.compile(r"(?m)^\s{0,3}#{1,6}[ \t]+(.+?)[ \t]*$")
_LINK_RE = re.compile(r"\[([^\]]+)\]\((?:https?://|mailto:)[^)\s]+\)")
_CODESPAN_RE = re.compile(r"`([^`\n]+)`")
_STRONG_RE = re.compile(r"\*\*([^*\n]+)\*\*|__([^_\n]+)__")
_FENCE_LINE_RE = re.compile(r"(?m)^\s*```.*$")
_QUOTE_RE = re.compile(r"(?m)^[ \t]{0,3}>[ \t]?")
_STRONG_SPAN_RE = re.compile(
    r"\*\*(?=[A-Za-z0-9_])([^*\n]+)\n([^*\n]+?)(?<=\w)\*\*(?![*/])"
)
_STRUCTURAL_HEADINGS = frozenset({
    "summary", "impact", "description", "details", "vulnerability",
    "affected versions", "affected packages", "patches", "patch",
    "workaround", "workarounds", "mitigation", "mitigations",
    "references", "reference", "credits", "credit", "acknowledgments",
    "acknowledgements", "timeline", "severity", "proof of concept",
    "poc", "exploit", "scope",
})

# ---------------------------------------------------------------------------
# CVSS v3 weights
# ---------------------------------------------------------------------------
_CVSS3_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS3_PRIVILEGES = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}
_SEVERITY_BANDS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.0, "LOW"))

# ---------------------------------------------------------------------------
# CVSS v4 lookup table (macro-vector -> score)
# ---------------------------------------------------------------------------
_CVSS4_LOOKUP = {
    "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5,
    "000020": 9.5, "000021": 9.2, "000100": 10, "000101": 9.6,
    "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8,
    "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5,
    "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1,
    "001120": 8.1, "001121": 6.5, "001200": 8.8, "001201": 8,
    "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
    "002111": 6.9, "002121": 5, "002201": 6.9, "002211": 5.5,
    "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5,
    "010101": 9.1, "010110": 9, "010111": 8.3, "010120": 8.4,
    "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5,
    "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5,
    "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8,
    "011111": 7.2, "011120": 7, "011121": 5.9, "011200": 8.4,
    "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5,
    "011221": 3, "012001": 8.6, "012011": 7.5, "012021": 5.2,
    "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3,
    "012211": 2.9, "012221": 1.7, "100000": 9.8, "100001": 9.5,
    "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4,
    "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5,
    "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7,
    "101020": 7.6, "101021": 6.7, "101100": 8.6, "101101": 7.6,
    "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2,
    "101220": 5.2, "101221": 2.5, "102001": 8.3, "102011": 7,
    "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5,
    "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6,
    "110021": 7, "110100": 9, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7,
    "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2,
    "110221": 3, "111000": 8.9, "111001": 7.8, "111010": 7.6,
    "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
    "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7,
    "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1,
    "112011": 5.9, "112021": 3, "112101": 5.8, "112111": 2.6,
    "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2,
    "200020": 7.5, "200021": 5.8, "200100": 8.6, "200101": 7.4,
    "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4,
    "200220": 4, "200221": 2.2, "201000": 8.5, "201001": 7.5,
    "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1,
    "201120": 4.6, "201121": 1.9, "201200": 5.3, "201201": 3.6,
    "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7,
    "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9,
    "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
    "210011": 5.3, "210020": 6, "210021": 5, "210100": 7.3,
    "210101": 5.5, "210110": 5.9, "210111": 4, "210120": 4.1,
    "210121": 2, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2, "210221": 1.1, "211000": 7.5,
    "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4,
    "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
    "211111": 1.8, "211120": 2, "211121": 0.9, "211200": 4.6,
    "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8,
    "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1,
    "212211": 0.3, "212221": 0.1,
}

# ============================================================================
# CVSS scoring (v3 and v4, dependency-free)
# ============================================================================

def _cvss4_round(value: float) -> float:
    return float(Decimal(value + 1e-6).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def _cvss4_m(metrics: dict, key: str) -> str:
    value = metrics.get(key, "X")
    if key == "E" and value == "X":
        return "A"
    if key in ("CR", "IR", "AR") and value == "X":
        return "H"
    modified = metrics.get(f"M{key}")
    if modified is not None and modified != "X":
        return modified
    return value


_CVSS4_MANDATORY = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
_CVSS4_IMPACT = ("VC", "VI", "VA", "SC", "SI", "SA")
_CVSS4_VALUES: dict[str, frozenset] = {
    "AV": frozenset("NALP"), "AC": frozenset("LH"), "AT": frozenset("NP"),
    "PR": frozenset("NLH"), "UI": frozenset("NPA"),
    "VC": frozenset("HLN"), "VI": frozenset("HLN"), "VA": frozenset("HLN"),
    "SC": frozenset("HLN"), "SI": frozenset("HLN"), "SA": frozenset("HLN"),
    "E": frozenset("XAPU"), "CR": frozenset("XMLH"), "IR": frozenset("XMLH"),
    "AR": frozenset("XMLH"), "MAV": frozenset("XNALP"), "MAC": frozenset("XLH"),
    "MAT": frozenset("XNP"), "MPR": frozenset("XNLH"), "MUI": frozenset("XNPA"),
    "MVC": frozenset("XHLN"), "MVI": frozenset("XHLN"), "MVA": frozenset("XHLN"),
    "MSC": frozenset("XHLN"), "MSI": frozenset("XSHLN"), "MSA": frozenset("XSHLN"),
    "S": frozenset("XNP"), "AU": frozenset("XNY"), "R": frozenset("XAUI"),
    "V": frozenset("XDC"), "RE": frozenset("XLMH"),
    "U": frozenset(("X", "CLEAR", "GREEN", "AMBER", "RED")),
}
_CVSS4_MODIFIED = (
    ("MAV","AV"),("MAC","AC"),("MAT","AT"),("MPR","PR"),("MUI","UI"),
    ("MVC","VC"),("MVI","VI"),("MVA","VA"),("MSC","SC"),("MSI","SI"),("MSA","SA"),
)
_CVSS4_LEVELS = {
    "AV":{"N":0.0,"A":0.1,"L":0.2,"P":0.3}, "PR":{"N":0.0,"L":0.1,"H":0.2},
    "UI":{"N":0.0,"P":0.1,"A":0.2}, "AC":{"L":0.0,"H":0.1}, "AT":{"N":0.0,"P":0.1},
    "VC":{"H":0.0,"L":0.1,"N":0.2}, "VI":{"H":0.0,"L":0.1,"N":0.2},
    "VA":{"H":0.0,"L":0.1,"N":0.2}, "SC":{"H":0.1,"L":0.2,"N":0.3},
    "SI":{"S":0.0,"H":0.1,"L":0.2,"N":0.3}, "SA":{"S":0.0,"H":0.1,"L":0.2,"N":0.3},
    "CR":{"H":0.0,"M":0.1,"L":0.2}, "IR":{"H":0.0,"M":0.1,"L":0.2},
    "AR":{"H":0.0,"M":0.1,"L":0.2},
}
_CVSS4_MAX_COMPOSED = {
    "eq1": {"0":["AV:N/PR:N/UI:N/"],"1":["AV:A/PR:N/UI:N/","AV:N/PR:L/UI:N/","AV:N/PR:N/UI:P/"],"2":["AV:P/PR:N/UI:N/","AV:A/PR:L/UI:P/"]},
    "eq2": {"0":["AC:L/AT:N/"],"1":["AC:H/AT:N/","AC:L/AT:P/"]},
    "eq3": {"0":{"0":["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],"1":["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/","VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]},"1":{"0":["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/","VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],"1":["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/","VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/","VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/","VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/","VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]},"2":{"1":["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]}},
    "eq4": {"0":["SC:H/SI:S/SA:S/"],"1":["SC:H/SI:H/SA:H/"],"2":["SC:L/SI:L/SA:L/"]},
    "eq5": {"0":["E:A/"],"1":["E:P/"],"2":["E:U/"]},
}
_CVSS4_MAX_SEVERITY = {
    "eq1":{0:1,1:4,2:5},"eq2":{0:1,1:2},
    "eq3eq6":{0:{0:7,1:6},1:{0:8,1:8},2:{1:10}},
    "eq4":{0:6,1:5,2:4},"eq5":{0:1,1:1,2:1},
}


def _cvss4_macro_vector(metrics: dict) -> str:
    if _cvss4_m(metrics,"AV")=="N" and _cvss4_m(metrics,"PR")=="N" and _cvss4_m(metrics,"UI")=="N":
        eq1="0"
    elif (_cvss4_m(metrics,"AV")=="N" or _cvss4_m(metrics,"PR")=="N" or _cvss4_m(metrics,"UI")=="N") and not (_cvss4_m(metrics,"AV")=="N" and _cvss4_m(metrics,"PR")=="N" and _cvss4_m(metrics,"UI")=="N") and _cvss4_m(metrics,"AV")!="P":
        eq1="1"
    else:
        eq1="2"
    eq2="0" if _cvss4_m(metrics,"AC")=="L" and _cvss4_m(metrics,"AT")=="N" else "1"
    if _cvss4_m(metrics,"VC")=="H" and _cvss4_m(metrics,"VI")=="H": eq3="0"
    elif _cvss4_m(metrics,"VC")=="H" or _cvss4_m(metrics,"VI")=="H" or _cvss4_m(metrics,"VA")=="H": eq3="1"
    else: eq3="2"
    if _cvss4_m(metrics,"MSI")=="S" or _cvss4_m(metrics,"MSA")=="S": eq4="0"
    elif _cvss4_m(metrics,"SC")=="H" or _cvss4_m(metrics,"SI")=="H" or _cvss4_m(metrics,"SA")=="H": eq4="1"
    else: eq4="2"
    eq5={"A":"0","P":"1","U":"2"}[_cvss4_m(metrics,"E")]
    if (_cvss4_m(metrics,"CR")=="H" and _cvss4_m(metrics,"VC")=="H") or (_cvss4_m(metrics,"IR")=="H" and _cvss4_m(metrics,"VI")=="H") or (_cvss4_m(metrics,"AR")=="H" and _cvss4_m(metrics,"VA")=="H"):
        eq6="0"
    else:
        eq6="1"
    return eq1+eq2+eq3+eq4+eq5+eq6


def _cvss4_extract(metric: str, composed: str) -> str:
    tail = composed[composed.index(metric)+len(metric)+1:]
    return tail.split("/",1)[0]


def _cvss4_score(metrics: dict) -> float:
    macro = _cvss4_macro_vector(metrics)
    if all(_cvss4_m(metrics,k)=="N" for k in _CVSS4_IMPACT):
        return 0.0
    value = _CVSS4_LOOKUP[macro]
    eq1_val,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val = (int(d) for d in macro)
    eq1_next="".join(str(d) for d in (eq1_val+1,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val))
    eq2_next="".join(str(d) for d in (eq1_val,eq2_val+1,eq3_val,eq4_val,eq5_val,eq6_val))
    if (eq3_val==1 or eq3_val==0) and eq6_val==1:
        eq3eq6_next="".join(str(d) for d in (eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val))
    elif eq3_val==1 and eq6_val==0:
        eq3eq6_next="".join(str(d) for d in (eq1_val,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val+1))
    elif eq3_val==0 and eq6_val==0:
        eq3eq6_left="".join(str(d) for d in (eq1_val,eq2_val,eq3_val,eq4_val,eq5_val,eq6_val+1))
        eq3eq6_right="".join(str(d) for d in (eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val))
    else:
        eq3eq6_next="".join(str(d) for d in (eq1_val,eq2_val,eq3_val+1,eq4_val,eq5_val,eq6_val+1))
    eq4_next="".join(str(d) for d in (eq1_val,eq2_val,eq3_val,eq4_val+1,eq5_val,eq6_val))
    eq5_next="".join(str(d) for d in (eq1_val,eq2_val,eq3_val,eq4_val,eq5_val+1,eq6_val))
    nan=float("nan")
    score_eq1_next=_CVSS4_LOOKUP.get(eq1_next,nan)
    score_eq2_next=_CVSS4_LOOKUP.get(eq2_next,nan)
    if eq3_val==0 and eq6_val==0:
        score_eq3eq6_next=max(_CVSS4_LOOKUP.get(eq3eq6_left,nan),_CVSS4_LOOKUP.get(eq3eq6_right,nan))
    else:
        score_eq3eq6_next=_CVSS4_LOOKUP.get(eq3eq6_next,nan)
    score_eq4_next=_CVSS4_LOOKUP.get(eq4_next,nan)
    score_eq5_next=_CVSS4_LOOKUP.get(eq5_next,nan)
    eq1_maxes=_CVSS4_MAX_COMPOSED["eq1"][str(eq1_val)]
    eq2_maxes=_CVSS4_MAX_COMPOSED["eq2"][str(eq2_val)]
    eq3_eq6_maxes=_CVSS4_MAX_COMPOSED["eq3"][str(eq3_val)][str(eq6_val)]
    eq4_maxes=_CVSS4_MAX_COMPOSED["eq4"][str(eq4_val)]
    eq5_maxes=_CVSS4_MAX_COMPOSED["eq5"][str(eq5_val)]
    max_vectors=[eq1+eq2+eq3+eq4+eq5 for eq1 in eq1_maxes for eq2 in eq2_maxes for eq3 in eq3_eq6_maxes for eq4 in eq4_maxes for eq5 in eq5_maxes]
    distance: dict[str,float]={}
    for composed in max_vectors:
        distance={key:_CVSS4_LEVELS[key][_cvss4_m(metrics,key)]-_CVSS4_LEVELS[key][_cvss4_extract(key,composed)] for key in ("AV","PR","UI","AC","AT","VC","VI","VA","CR","IR","AR","SC","SI","SA")}
        if all(v>=0 for v in distance.values()):
            break
    current_eq1=distance["AV"]+distance["PR"]+distance["UI"]
    current_eq2=distance["AC"]+distance["AT"]
    current_eq3eq6=distance["VC"]+distance["VI"]+distance["VA"]+distance["CR"]+distance["IR"]+distance["AR"]
    current_eq4=distance["SC"]+distance["SI"]+distance["SA"]
    available_eq1=value-score_eq1_next
    available_eq2=value-score_eq2_next
    available_eq3eq6=value-score_eq3eq6_next
    available_eq4=value-score_eq4_next
    available_eq5=value-score_eq5_next
    max_severity_eq1=_CVSS4_MAX_SEVERITY["eq1"][eq1_val]*0.1
    max_severity_eq2=_CVSS4_MAX_SEVERITY["eq2"][eq2_val]*0.1
    max_severity_eq3eq6=_CVSS4_MAX_SEVERITY["eq3eq6"][eq3_val][eq6_val]*0.1
    max_severity_eq4=_CVSS4_MAX_SEVERITY["eq4"][eq4_val]*0.1
    normalized: list[float]=[]
    if available_eq1>=0: normalized.append(available_eq1*(current_eq1/max_severity_eq1))
    if available_eq2>=0: normalized.append(available_eq2*(current_eq2/max_severity_eq2))
    if available_eq3eq6>=0: normalized.append(available_eq3eq6*(current_eq3eq6/max_severity_eq3eq6))
    if available_eq4>=0: normalized.append(available_eq4*(current_eq4/max_severity_eq4))
    if available_eq5>=0: normalized.append(0.0)
    if not normalized: return _cvss4_round(value)
    mean_distance=sum(normalized)/len(normalized)
    return _cvss4_round(min(10.0,max(0.0,value-mean_distance)))


def _cvss4_base_score(vector: str) -> float | None:
    text = str(vector or "").strip()
    if not text.upper().startswith("CVSS:4.0/"):
        return None
    metrics: dict[str, str] = {}
    for field in text.split("/")[1:]:
        if not field:
            return None
        key, sep, value = field.partition(":")
        if not sep:
            return None
        key, value = key.strip().upper(), value.strip().upper()
        allowed = _CVSS4_VALUES.get(key)
        if allowed is None or value not in allowed or key in metrics:
            return None
        metrics[key] = value
    if any(key not in metrics for key in _CVSS4_MANDATORY):
        return None
    for modified, base in _CVSS4_MODIFIED:
        if metrics.get(modified) in (None, "X"):
            metrics[modified] = metrics[base]
    try:
        return _cvss4_score(metrics)
    except (KeyError, ValueError, IndexError, ZeroDivisionError):
        return None


def _cvss3_base_score(vector: str) -> float | None:
    text = str(vector or "").strip()
    if text.upper().startswith("CVSS:4"):
        return _cvss4_base_score(text)
    if text.upper().startswith("CVSS:3"):
        _, sep, tail = text.partition("/")
        if not sep:
            return None
        text = tail
    metrics: dict[str, str] = {}
    for part in text.split("/"):
        part = part.strip()
        if not part:
            continue
        key, sep, value = part.partition("=")
        if not sep:
            key, sep, value = part.partition(":")
        if not sep:
            continue
        key, value = key.strip().upper(), value.strip().upper()
        if key in _CVSS3_METRICS and value:
            metrics[key] = value
    if not all(m in metrics for m in _CVSS3_METRICS):
        return None
    scope = metrics.get("S", "U")
    try:
        exploitability = (
            8.22
            * _CVSS3_WEIGHTS["AV"][metrics["AV"]]
            * _CVSS3_WEIGHTS["AC"][metrics["AC"]]
            * _CVSS3_PRIVILEGES[scope][metrics["PR"]]
            * _CVSS3_WEIGHTS["UI"][metrics["UI"]]
        )
        c = _CVSS3_WEIGHTS["C"][metrics["C"]]
        i = _CVSS3_WEIGHTS["I"][metrics["I"]]
        a = _CVSS3_WEIGHTS["A"][metrics["A"]]
        iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = min(impact + exploitability, 10.0)
    return math.ceil(raw * 10) / 10.0


def _cvss_base_score(vector: str) -> float | None:
    text = str(vector or "").strip()
    if not text:
        return None
    if text.upper().startswith("CVSS:4"):
        return _cvss4_base_score(text)
    return _cvss3_base_score(text)


def _severity_for_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    for floor, label in _SEVERITY_BANDS:
        if score >= floor:
            return label
    return "UNKNOWN"


def _normalize_severity(value: str | None, score: float | None = None) -> str:
    if score is not None:
        return _severity_for_score(score)
    label = str(value or "").strip().upper()
    if label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return label
    if label == "MODERATE":
        return "MEDIUM"
    return "UNKNOWN"


# ============================================================================
# Description normalization
# ============================================================================

def _normalize_description(text) -> str:
    raw = str(text or "")
    if not raw.strip():
        return ""
    out = _FENCE_LINE_RE.sub("", raw)
    for _ in range(10):
        previous = out
        out = _LINK_RE.sub(r"\1", out)
        out = _CODESPAN_RE.sub(r"\1", out)
        out = _STRONG_RE.sub(lambda m: m.group(1) or m.group(2) or "", out)
        out = _STRONG_SPAN_RE.sub(lambda m: f"{m.group(1)}\n{m.group(2)}", out)
        if out == previous:
            break
    out = _QUOTE_RE.sub("", out)
    kept: list[str] = []
    for line in out.splitlines():
        heading = _HEADING_RE.match(line)
        if heading:
            label = heading.group(1).strip().rstrip(":").strip()
            if label.lower() in _STRUCTURAL_HEADINGS:
                continue
            kept.append(label)
            continue
        kept.append(line.rstrip())
    out = re.sub(r"[ \t]+\n", "\n", "\n".join(kept))
    out = re.sub(r"\n{3,}", "\n\n", out).strip()
    if not out:
        return ""
    if len(out) > _MAX_DESCRIPTION:
        cut = out[:_MAX_DESCRIPTION - 1].rsplit(" ", 1)[0].rstrip(" ,;:")
        out = (cut or out[:_MAX_DESCRIPTION - 1]) + "…"
    return out


# ============================================================================
# Version range evaluation (OSV semantics, dependency-free)
# ============================================================================

_SPLIT_RE = re.compile(r"[.\-+_~]|(?<=\d)(?=[A-Za-z])|(?<=[A-Za-z])(?=\d)")
_SEMVER_RANGE_TYPES = frozenset({"SEMVER", "ECOSYSTEM"})


def _parse_version(version: str) -> list | None:
    raw = str(version or "").strip()
    if not raw or len(raw) > 200 or " " in raw:
        return None
    if any(ch in raw for ch in "<>!=|^&*"):
        return None
    raw = raw.split("+", 1)[0].strip()
    if not raw:
        return None
    tokens: list = []
    for chunk in _SPLIT_RE.split(raw):
        if not chunk:
            continue
        if chunk.isdigit() and len(chunk) <= 12:
            tokens.append(int(chunk))
        else:
            tokens.append(chunk.lower())
    if not tokens or "*" in raw or raw[0] in "xX":
        return None
    return tokens


def _compare_versions(a: str, b: str) -> int | None:
    ta, tb = _parse_version(a), _parse_version(b)
    if ta is None or tb is None:
        return None
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, int):
            return -1
        return 1
    if len(ta) == len(tb):
        return 0
    remaining = ta[len(tb):] if len(ta) > len(tb) else tb[len(ta):]
    if isinstance(remaining[0], int):
        return 1 if len(ta) > len(tb) else -1
    return -1 if len(ta) > len(tb) else 1


def _versions_equal(a: str, b: str) -> bool | None:
    if str(a).strip() == str(b).strip():
        return True
    cmp = _compare_versions(a, b)
    if cmp is None:
        return None
    return cmp == 0


def _in_events(installed: str, events: list) -> bool | None:
    if not events or not isinstance(events, list):
        return None
    vulnerable = False
    evaluable = False
    broken = False
    introduced: str | None = None
    for event in events:
        if not isinstance(event, dict):
            broken = True
            continue
        if "introduced" in event:
            introduced = str(event.get("introduced") or "")
        elif "fixed" in event or "last_affected" in event:
            bound_key = "fixed" if "fixed" in event else "last_affected"
            bound = str(event.get(bound_key) or "")
            if introduced is not None:
                low = _compare_versions(installed, introduced)
                high = _compare_versions(installed, bound)
                if low is None or high is None:
                    broken = True
                else:
                    evaluable = True
                    if bound_key == "fixed":
                        if low >= 0 and high < 0:
                            vulnerable = True
                    elif low >= 0 and high <= 0:
                        vulnerable = True
            introduced = None
        elif "limit" in event:
            introduced = None
    if vulnerable:
        return True
    if broken and not evaluable:
        return None
    if broken:
        return None
    return False if evaluable else None


def _evaluate_affected(installed: str, affected_entries: list[dict]) -> bool | None:
    if not affected_entries:
        return None
    version = str(installed or "").strip()
    if not version:
        return None
    any_true = False
    any_broken = False
    for entry in affected_entries:
        if not isinstance(entry, dict):
            any_broken = True
            continue
        versions = entry.get("versions") or []
        if isinstance(versions, list):
            for known in versions:
                eq = _versions_equal(version, str(known))
                if eq:
                    any_true = True
                    break
                if eq is None:
                    any_broken = True
            if any_true:
                continue
        ranges = entry.get("ranges") or []
        if not ranges and not versions:
            any_true = True
            continue
        if not isinstance(ranges, list):
            any_broken = True
            continue
        entry_evaluable = False
        entry_broken = False
        for rng in ranges:
            if not isinstance(rng, dict):
                entry_broken = True
                continue
            if rng.get("type") not in _SEMVER_RANGE_TYPES:
                entry_broken = True
                continue
            result = _in_events(version, rng.get("events") or [])
            if result is True:
                any_true = True
                entry_evaluable = True
                break
            if result is None:
                entry_broken = True
            else:
                entry_evaluable = True
        if entry_evaluable:
            any_broken = any_broken and not any_true
        if entry_broken:
            any_broken = True
    if any_true:
        return True
    if any_broken:
        return None
    return False


def _fixed_versions_of(affected_entries: list[dict]) -> list[str]:
    fixed: list[str] = []
    for entry in affected_entries:
        if not isinstance(entry, dict):
            continue
        for rng in entry.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    value = str(event["fixed"])
                    if value not in fixed:
                        fixed.append(value)
    return fixed


# ============================================================================
# Rate limiter + HTTP client (dependency-free except httpx)
# ============================================================================

class _RateLimiter:
    def __init__(self, requests_per_second: float = 5.0, burst: int = 10):
        self._rate = requests_per_second
        self._burst = burst
        self._tokens: dict[str, float] = defaultdict(lambda: float(burst))
        self._last_refill: dict[str, float] = defaultdict(time.monotonic)
        self._lock = threading.Lock()

    def acquire(self, domain: str) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill[domain]
            self._tokens[domain] = min(self._burst, self._tokens[domain] + elapsed * self._rate)
            self._last_refill[domain] = now
            if self._tokens[domain] < 1.0:
                wait_time = (1.0 - self._tokens[domain]) / self._rate
                self._tokens[domain] = 0.0
            else:
                self._tokens[domain] -= 1.0
                wait_time = 0.0
        if wait_time > 0:
            time.sleep(wait_time)


_NVD_HAS_KEY = bool((os.getenv("SCA_NVD_API_KEY") or "").strip())
_OSV_LIMITER = _RateLimiter(requests_per_second=10.0, burst=20)
_NVD_LIMITER = _RateLimiter(
    requests_per_second=1.66 if _NVD_HAS_KEY else 0.166,
    burst=10 if _NVD_HAS_KEY else 5,
)


class _RetryClient:
    def __init__(self, timeout: float = 15.0, max_retries: int = 3):
        import httpx as _httpx
        self._client = _httpx.Client(timeout=timeout)
        self._max_retries = max_retries
        self._timeout = timeout

    def get(self, url: str, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self._request("POST", url, **kwargs)

    def _request(self, method: str, url: str, **kwargs):
        import httpx as _httpx
        kwargs.setdefault("timeout", self._timeout)
        for attempt in range(self._max_retries):
            try:
                resp = self._client.request(method, url, **kwargs)
                if resp.status_code < 500:
                    return resp
                if attempt < self._max_retries - 1:
                    time.sleep(1.0 * (2 ** attempt))
            except _httpx.TimeoutException:
                if attempt < self._max_retries - 1:
                    time.sleep(1.0 * (2 ** attempt))
            except _httpx.RequestError as e:
                logger.warning("Request failed for %s: %s", url, e)
                return None
        return None

    def close(self):
        self._client.close()


# ============================================================================
# In-memory + disk cache (session-scoped, keyed by ecosystem:package)
# ============================================================================

class _ScanCache:
    def __init__(self, ttl_seconds: int = 3600):
        import tempfile
        self._ttl = ttl_seconds
        self._mem: dict[str, tuple[float, object]] = {}
        self._lock = threading.Lock()
        self._dir = Path(tempfile.gettempdir()) / "sca-cache"
        self._dir.mkdir(parents=True, exist_ok=True)

    def _hk(self, key: str) -> str:
        import hashlib
        return hashlib.sha256(key.encode()).hexdigest()

    def get(self, key: str):
        with self._lock:
            entry = self._mem.get(key)
            if entry and time.time() - entry[0] < self._ttl:
                return entry[1]
        path = self._dir / f"{self._hk(key)}.json"
        if path.exists():
            try:
                import json
                data = json.loads(path.read_text(encoding="utf-8"))
                if time.time() - data.get("ts", 0) < self._ttl:
                    with self._lock:
                        self._mem[key] = (time.time(), data["value"])
                    return data["value"]
                path.unlink()
            except Exception:
                pass
        return None

    def set(self, key: str, value) -> None:
        with self._lock:
            self._mem[key] = (time.time(), value)
        try:
            import json
            (self._dir / f"{self._hk(key)}.json").write_text(
                json.dumps({"ts": time.time(), "value": value}), encoding="utf-8"
            )
        except Exception:
            pass


_CACHE = _ScanCache()


# ============================================================================
# OSV querying
# ============================================================================

def _osv_query_name(ecosystem: str, name: str) -> str:
    if str(ecosystem or "").lower() not in _MAVEN_ECOSYSTEMS:
        return name
    name = str(name or "")
    if not name or ":" in name:
        return name
    return name.replace("/", ":", 1) if "/" in name else name


def _osv_query_package(client: _RetryClient, ecosystem: str, name: str) -> list[dict] | None:
    eco = _OSV_ECOSYSTEM_MAP.get(str(ecosystem or "").lower())
    if not eco or not name:
        return None
    osv_name = _osv_query_name(ecosystem, name)
    cache_key = f"osv:{ecosystem}:{osv_name}"
    cached = _CACHE.get(cache_key)
    if isinstance(cached, list):
        return cached
    collected: list[dict] = []
    page_token = ""
    for _ in range(_OSV_MAX_PAGES):
        payload: dict = {"package": {"ecosystem": eco, "name": osv_name}}
        if page_token:
            payload["page_token"] = page_token
        try:
            _OSV_LIMITER.acquire("api.osv.dev")
            resp = client.post(_OSV_BASE + "/query", json=payload, headers=_OSV_HEADERS)
        except Exception as e:
            logger.warning("OSV query failed for %s/%s: %s", ecosystem, name, e)
            return None
        if resp is None or resp.status_code != 200:
            return None
        if len(resp.content) > _OSV_MAX_RESPONSE_BYTES:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        for entry in data.get("vulns") or []:
            if isinstance(entry, dict) and str(entry.get("id") or "").strip():
                collected.append(entry)
        page_token = str(data.get("next_page_token") or "")
        if not page_token:
            break
    _CACHE.set(cache_key, collected)
    return collected


# ============================================================================
# NVD CVSS enrichment
# ============================================================================

def _nvd_fetch(client: _RetryClient, cve_id: str) -> dict | None:
    cve = str(cve_id or "").strip().upper()
    if not _CVE_ID_RE.match(cve):
        return None
    cache_key = f"nvd:{cve}"
    cached = _CACHE.get(cache_key)
    if isinstance(cached, dict) and isinstance(cached.get("score"), (int, float)):
        return {"score": float(cached["score"]), "vector": str(cached.get("vector") or "")}
    headers = dict(_NVD_HEADERS)
    api_key = (os.getenv("SCA_NVD_API_KEY") or "").strip()
    if api_key:
        headers["apiKey"] = api_key
    try:
        _NVD_LIMITER.acquire("services.nvd.nist.gov")
        resp = client.get(_NVD_BASE, params={"cveId": cve}, headers=headers)
    except Exception as e:
        logger.warning("NVD lookup failed for %s: %s", cve, e)
        return None
    if resp is None or resp.status_code == 404:
        return None
    if resp.status_code != 200 or len(resp.content) > _NVD_MAX_RESPONSE_BYTES:
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    try:
        vulns = payload.get("vulnerabilities")
        if not isinstance(vulns, list) or not vulns:
            return None
        cve_data = vulns[0].get("cve") or {}
        metrics = cve_data.get("metrics")
        if not isinstance(metrics, dict):
            return None
        entry = None
        for block in _NVD_METRIC_BLOCKS:
            entries = metrics.get(block)
            if not isinstance(entries, list):
                continue
            usable = [e for e in entries if isinstance(e, dict) and isinstance(e.get("cvssData"), dict)]
            if usable:
                usable.sort(key=lambda e: str(e.get("type") or "") != "Primary")
                entry = usable[0]
                break
        if entry is None:
            return None
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        if not isinstance(score, (int, float)) or isinstance(score, bool):
            return None
        result = {"score": float(score), "vector": str(data.get("vectorString") or "")}
        _CACHE.set(cache_key, result)
        return result
    except (AttributeError, IndexError, TypeError, ValueError):
        return None


def _enrich_cvss(findings: list[dict], client: _RetryClient) -> None:
    buckets: dict[str, list[dict]] = {}
    for finding in findings:
        if finding.get("cvss_score") is not None:
            continue
        candidates = [finding.get("vulnerability_id"), *(finding.get("aliases") or [])]
        cve = next((c.upper() for c in candidates if isinstance(c, str) and c.upper().startswith("CVE-")), "")
        if cve:
            buckets.setdefault(cve, []).append(finding)
    cve_order = sorted(
        buckets,
        key=lambda c: (
            0 if any(f.get("match_status") == MATCH_VULNERABLE for f in buckets[c]) else 1,
            c,
        ),
    )
    for i, cve in enumerate(cve_order):
        if i >= _MAX_CVSS_ENRICH_LOOKUPS:
            break
        result = _nvd_fetch(client, cve)
        if result is None:
            continue
        for finding in buckets[cve]:
            finding["cvss_score"] = result["score"]
            finding["cvss_vector"] = result["vector"]
            finding["severity"] = _severity_for_score(result["score"])


# ============================================================================
# Record normalization
# ============================================================================

_CVSS_TYPES = frozenset({"CVSS_V3", "CVSS_V3.0", "CVSS_V3.1", "CVSS_V4", "CVSS_V4.0"})


def _primary_id(record_id: str, aliases: list[str]) -> tuple[str, list[str]]:
    record_id = str(record_id or "").strip()
    all_aliases = [str(a).strip() for a in aliases if str(a or "").strip()]
    deduped = list(dict.fromkeys([record_id, *all_aliases]))
    if record_id.upper().startswith("CVE-"):
        return record_id.upper(), [a for a in deduped if a != record_id]
    for alias in deduped:
        if alias.upper().startswith("CVE-"):
            return alias.upper(), [a for a in deduped if a != alias]
    return record_id, [a for a in deduped if a != record_id]


def _cvss_from_record(record: dict) -> tuple[str, float | None]:
    for entry in record.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("type") or "").upper() in _CVSS_TYPES:
            raw = str(entry.get("score") or "").strip()
            if not raw:
                continue
            try:
                return raw, float(raw)
            except ValueError:
                return raw, _cvss_base_score(raw)
    return "", None


def _matching_affected_entries(record: dict, ecosystem: str, name: str) -> list[dict]:
    matches: list[dict] = []
    for entry in record.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        entry_name = str(package.get("name") or "")
        entry_eco = str(package.get("ecosystem") or "")
        if not entry_name:
            continue
        if entry_name != name and entry_name.casefold() != name.casefold():
            continue
        if entry_eco and ecosystem and entry_eco != ecosystem:
            continue
        matches.append(entry)
    return matches


def _extract_cwe_ids(vuln: dict) -> list[str]:
    db_specific = vuln.get("database_specific") or {}
    cwe_ids: list[str] = list(db_specific.get("cwe_ids") or [])
    if not cwe_ids:
        for affected in vuln.get("affected") or []:
            for cwe in (affected.get("database_specific") or {}).get("cwe_ids") or []:
                if cwe not in cwe_ids:
                    cwe_ids.append(cwe)
    return cwe_ids


def _normalize_record(record: dict, ecosystem: str, package_name: str, component: dict) -> dict | None:
    if not isinstance(record, dict) or not str(record.get("id") or "").strip():
        return None
    try:
        aliases = [str(a) for a in (record.get("aliases") or []) if a]
        vuln_id, alias_list = _primary_id(str(record["id"]), aliases)
        entries = _matching_affected_entries(record, ecosystem, package_name)
        vector, score = _cvss_from_record(record)

        # Severity label: score band wins when available; fall back to db_specific labels
        severity = None
        for candidate_src in [
            (record.get("database_specific") or {}).get("severity"),
            (record.get("ecosystem_specific") or {}).get("severity"),
        ] + [(e.get("database_specific") or {}).get("severity") for e in entries]:
            s = _normalize_severity(candidate_src, score)
            if s != "UNKNOWN":
                severity = s
                break
        if severity is None:
            severity = _normalize_severity(None, score) or "MEDIUM"

        description = _normalize_description(
            record.get("details") or record.get("summary") or ""
        )
        references = [
            str(ref.get("url"))
            for ref in (record.get("references") or [])
            if isinstance(ref, dict) and ref.get("url")
        ][:_MAX_REFERENCES]

        affected_versions: list[str] = []
        for entry in entries:
            for v in entry.get("versions") or []:
                val = str(v)
                if val and val not in affected_versions and len(affected_versions) < _MAX_AFFECTED_VERSIONS:
                    affected_versions.append(val)

        affected_ranges: list[dict] = []
        for entry in entries:
            for rng in entry.get("ranges") or []:
                if isinstance(rng, dict) and len(affected_ranges) < _MAX_RANGES:
                    affected_ranges.append(rng)

        fixed_versions = _fixed_versions_of(entries)
        installed = str(component.get("version") or "")

        match_status = MATCH_NOT_EVALUABLE
        if installed and entries:
            verdict = _evaluate_affected(installed, [{
                "ranges": affected_ranges,
                "versions": affected_versions,
            }])
            if verdict is True:
                match_status = MATCH_VULNERABLE
            elif verdict is False:
                match_status = MATCH_NOT_AFFECTED_BY_VERSION

        return {
            "vulnerability_id": vuln_id,
            "aliases": alias_list,
            # Legacy-compat fields
            "id": vuln_id,
            "summary": description,
            "details": description,
            "severity": severity,
            "cvss_score": score,
            "cvss_vector": vector,
            "cwe_ids": _extract_cwe_ids(record),
            "references": references,
            "published": str(record.get("published") or ""),
            "modified": str(record.get("modified") or ""),
            "match_status": match_status,
            "fixed_versions": fixed_versions,
            "affected_versions": affected_versions,
            "affected_ranges": affected_ranges,
        }
    except Exception as e:
        logger.debug("Skipping malformed OSV record %s: %s", record.get("id", "?"), e)
        return None


# ============================================================================
# Public API
# ============================================================================

def _infer_ecosystem(component: dict) -> str:
    purl = str(component.get("purl") or "")
    if purl.startswith("pkg:"):
        eco = purl[4:].split("/")[0].split("@")[0].split("?")[0].lower()
        return eco
    return str(component.get("ecosystem") or "").lower()


def _package_name(component: dict) -> str:
    name = str(component.get("name") or "")
    group = str(component.get("group") or "")
    if group and name:
        return f"{group}/{name}"
    return name


def run_sca(components: list[dict]) -> dict:
    """Query OSV.dev for known vulnerabilities across *components*.

    Uses per-package version-agnostic queries so that NOT_AFFECTED_BY_VERSION
    is observable, computes full CVSS v3/v4 scores locally, and fills missing
    scores from NVD for CVE-identified findings.

    Returns the same structure as the previous implementation so all call
    sites in scan_runner.py continue to work without changes.
    """
    try:
        import httpx  # noqa: F401 — confirm dependency is present
    except ImportError:
        logger.warning("httpx not installed; SCA scan skipped")
        return _empty_result(components)

    if not components:
        return _empty_result(components)

    client = _RetryClient(timeout=15.0, max_retries=3)
    all_findings: list[dict] = []
    vulnerabilities: list[dict] = []
    vex_statements: list[dict] = []

    # Group by (ecosystem, package_name) so each package is queried once
    # even when multiple components share the same package (different purls
    # but same name/version rarely happen, but deduping is free).
    pkg_to_components: dict[tuple[str, str], list[dict]] = {}
    for comp in components:
        if not comp.get("purl") and not comp.get("name"):
            continue
        eco = _infer_ecosystem(comp)
        name = _package_name(comp)
        if not name:
            name = str(comp.get("purl") or "")
        pkg_to_components.setdefault((eco, name), []).append(comp)

    for (ecosystem, pkg_name), comps in pkg_to_components.items():
        records = _osv_query_package(client, ecosystem, pkg_name)
        if records is None:
            logger.warning("OSV query failed for %s/%s — marking as incomplete", ecosystem, pkg_name)
            continue
        if not records:
            continue

        for comp in comps:
            purl = str(comp.get("purl") or "")
            version = str(comp.get("version") or "")
            display_name = str(comp.get("name") or pkg_name)

            comp_findings: list[dict] = []
            for record in records:
                normalized = _normalize_record(record, ecosystem, pkg_name, comp)
                if normalized is None:
                    continue
                normalized["component_purl"] = purl
                normalized["component_name"] = display_name
                normalized["installed_version"] = version
                comp_findings.append(normalized)
                all_findings.append(normalized)

            if not comp_findings:
                continue

            vulnerabilities.append({
                "purl": purl,
                "package_name": display_name,
                "version": version,
                "vuln_count": len(comp_findings),
                "vulns": comp_findings,
            })

            for finding in comp_findings:
                vuln_id = finding["vulnerability_id"]
                fixed = finding.get("fixed_versions") or []
                if finding["match_status"] == MATCH_NOT_AFFECTED_BY_VERSION:
                    status = "not_affected"
                    justification = f"Version {version} is not in the affected range"
                elif fixed:
                    status = "fixed"
                    justification = f"Fixed in: {', '.join(fixed[:3])}"
                else:
                    status = "affected"
                    justification = ""
                vex_statements.append({
                    "purl": purl,
                    "vuln_id": vuln_id,
                    "status": status,
                    "justification": justification,
                })

    # NVD CVSS enrichment for findings that have no score yet
    _enrich_cvss(all_findings, client)

    client.close()

    return {
        "vulnerabilities": vulnerabilities,
        "vex_statements": vex_statements,
        "component_count": len(components),
        "vulnerable_component_count": len(vulnerabilities),
    }


def _empty_result(components: list[dict]) -> dict:
    return {
        "vulnerabilities": [],
        "vex_statements": [],
        "component_count": len(components),
        "vulnerable_component_count": 0,
    }
