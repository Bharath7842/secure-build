"""Baseline CVSS v3.1 vector per CWE: the standard-based severity of a SAST finding.

Each vector scores the *typical exploitable instance* of the weakness, the way
NVD scores a CVE of that class. `app/services/severity.py` starts from it, lets
a catalog rule whose pattern is narrower than its CWE refine it (`cvss_vector`
on the rule), adjusts it with evidence the scanner has for the finding, and
takes the severity from the score's CVSS band.

Bump `SCHEME` whenever a vector changes, then re-score stored findings with
`scripts/rescore_severity.py`.
"""

from __future__ import annotations

SCHEME = "cvss31-cwe-1"

# A weakness that is exploitable from the network with no privileges or user
# action and compromises the whole application.
_FULL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8

# cwe number -> (vector, why this vector is the typical instance)
CWE_BASELINES: dict[int, tuple[str, str]] = {
    16: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "insecure configuration exposes limited information"),
    20: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "unvalidated input lets a remote user corrupt some data"),
    22: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "path traversal reads arbitrary files"),
    74: (_FULL, "JNDI/injection into a downstream interpreter leads to remote code execution"),
    78: (_FULL, "OS command injection runs attacker commands"),
    79: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "cross-site scripting runs script in a victim's browser"),
    89: (_FULL, "SQL injection reads and changes the database"),
    90: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "LDAP injection reads directory data or bypasses a filter"),
    94: (_FULL, "code injection runs attacker code"),
    95: (_FULL, "eval injection runs attacker code"),
    113: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "response splitting injects headers or content into a victim's response"),
    117: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", "log forging writes fake log entries"),
    185: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", "an incorrect or attacker-built regular expression degrades matching"),
    200: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "some sensitive information is exposed"),
    201: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "sensitive data is sent where it can be observed, under specific conditions"),
    203: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "an observable difference enumerates users or states"),
    209: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "error messages reveal internals"),
    250: ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L", "excess privilege worsens another flaw; not exploitable on its own"),
    256: ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "a plaintext password is readable by anyone with local access"),
    261: ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "an encoded password is as readable as a plaintext one"),
    269: ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "a low-privileged principal gains full control"),
    284: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "a resource is reachable by anyone it should not be"),
    287: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "authentication can be bypassed"),
    295: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", "a network attacker in the middle reads and changes traffic"),
    306: (_FULL, "a critical function needs no authentication"),
    311: ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "data stored unencrypted is readable with storage access"),
    319: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "cleartext traffic is readable by a network attacker in the middle"),
    326: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "weak encryption is broken with captured ciphertext"),
    327: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "a broken algorithm is broken with captured ciphertext"),
    328: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "a weak hash allows collisions or cracking"),
    329: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "a predictable IV leaks plaintext patterns"),
    330: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "predictable random values let tokens be guessed"),
    345: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "unverified data is trusted after a user action"),
    346: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "a message from any origin is trusted after a user action"),
    347: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "an unverified signature lets tokens be forged"),
    352: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "cross-site request forgery acts as the victim"),
    362: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", "a race corrupts some data under specific timing"),
    390: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", "a swallowed error leaves the application in a wrong state"),
    400: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "uncontrolled resource use denies service"),
    434: ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "an authenticated upload of an executable file leads to code execution"),
    470: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "attacker-chosen classes or methods are invoked"),
    476: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "a null dereference crashes the request or service"),
    489: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "debug features expose internals"),
    494: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "code downloaded without an integrity check can be replaced"),
    502: (_FULL, "deserializing untrusted data leads to remote code execution"),
    506: (_FULL, "embedded malicious code acts with the application's rights"),
    522: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "credentials are stored or sent where they can be taken"),
    532: ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "sensitive data in logs is readable by anyone with log access"),
    561: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "dead code has no direct security impact"),
    601: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "an open redirect sends a victim to an attacker's site"),
    602: ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "a check done only on the client is bypassed by a user"),
    611: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L", "an XML external entity reads files or makes requests"),
    613: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "a session that does not expire can be reused"),
    614: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "a cookie without Secure can leak over cleartext"),
    639: ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "a user reaches another user's records by changing an id"),
    643: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "XPath injection reads XML data"),
    693: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "a missing protection mechanism helps another attack"),
    759: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "unsalted hashes are cracked once the store leaks"),
    780: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "RSA without OAEP is open to padding attacks"),
    787: (_FULL, "an out-of-bounds write corrupts memory"),
    798: (_FULL, "a hard-coded credential gives anyone who reads the code access"),
    829: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "code from an untrusted source runs with the application's rights"),
    862: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "a sensitive function has no authorization check"),
    915: ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", "mass assignment lets a user set fields they should not"),
    916: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "a key or hash without a proper KDF is cracked offline"),
    917: (_FULL, "expression language injection runs attacker code"),
    918: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", "server-side request forgery reaches internal systems"),
    942: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", "a permissive CORS policy lets another site read a victim's data"),
    1004: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "a cookie without HttpOnly is readable by injected script"),
    1021: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "clickjacking tricks a victim into clicking"),
    1022: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", "an opened page can navigate its opener"),
    1104: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", "an unmaintained component carries unfixed flaws"),
    1188: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "an insecure default (such as a default credential) is usable as shipped"),
    1321: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", "prototype pollution changes the behaviour of other objects"),
    1336: (_FULL, "template injection runs attacker code"),
}
