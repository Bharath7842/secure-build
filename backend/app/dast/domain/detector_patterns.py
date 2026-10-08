"""Pattern data and tolerances for the detector library (DAST-04-020, -030).

Data only: extend a list here and the detectors pick it up. Patterns are regular
expressions matched case-insensitively against a response body excerpt. None of them
is a payload; they describe what a *target's response* looks like when it leaks.
"""

from __future__ import annotations

# Error text a database driver or ORM surfaces when input reached a query unsanitized.
DB_ERROR_PATTERNS: tuple[str, ...] = (
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysqli?_(?:query|fetch|num_rows)",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"\bora-\d{5}\b",
    r"pg_query\(\)|pg::syntaxerror|psycopg2?\.errors?\.|postgresql.{0,20}error",
    r"syntax error at or near",
    r"sqlstate\[[0-9a-z]{5}\]",
    r"sqlite(?:3)?[._ ](?:error|exception)|sqlite_error|near \".{0,20}\": syntax error",
    r"sqlsyntaxerrorexception|java\.sql\.sql\w*exception",
    r"microsoft ole db provider for sql server|\bodbc sql server driver\b",
    r"unterminated (?:quoted|string) (?:string|literal)",
    r"sequelize(?:database)?error|sqlalchemy\.exc\.",
)

# A stack trace or framework debug page: internals the response should never carry.
STACK_TRACE_PATTERNS: tuple[str, ...] = (
    r"traceback \(most recent call last\)",
    r"\bat [\w$.]+\([\w$]+\.java:\d+\)",
    r"exception in thread \"[^\"]+\"",
    r"\bat [\w.<>$`]+\([^)\n]*\) in [^\n]{1,200}:line \d+",  # .NET
    r"\bat (?:async )?[\w.<>$]+ \((?:/|[a-z]:\\)[^\n)]{1,200}:\d+:\d+\)",  # Node
    r"stack trace:\s*#0 ",  # PHP
    r"whitelabel error page",
    r"werkzeug debugger|django\.core\.exceptions|laravel.{0,40}exception",
    r"fatal error: uncaught",
)

# Output that only a shell could have produced (checked only when absent from the baseline).
COMMAND_OUTPUT_PATTERNS: tuple[str, ...] = (
    r"\buid=\d+\([\w-]+\)\s+gid=\d+",
    r"root:[x*!]:0:0:",
    r"volume serial number is",
    r"directory of [a-z]:\\",
    r"^total \d+\s*\n[-dl][rwx-]{9}",
    r"linux version \d+\.\d+",
    r"\bwindows ip configuration\b",
)

# The content of a file a path-traversal or local-file-include payload was never meant to reach.
FILE_DISCLOSURE_PATTERNS: tuple[str, ...] = (
    r"root:[x*!]:0:0:",  # /etc/passwd
    r"\[(?:fonts|extensions|mci extensions)\]",  # win.ini
    r"for 16-bit app support",  # win.ini
    r"\[boot loader\]",  # boot.ini
    r"-----BEGIN (?:RSA |OPENSSH |DSA |EC )?PRIVATE KEY-----",  # a key file read off disk
    r"^<\?php\b",  # unexecuted PHP source, not a rendered page
)

# Error text a NoSQL store's driver surfaces when input reached a query unsanitized.
NOSQL_ERROR_PATTERNS: tuple[str, ...] = (
    r"mongoerror|mongodb\.driver|bson\.errors",
    r"com\.mongodb\.",
    r"cannot convert undefined or null to object",
    r"redis\.exceptions\.|wrongtype operation",
    r"couchdb.{0,20}error|org\.elasticsearch\.",
)

# Error text an LDAP directory surfaces when a search filter was built by concatenating input.
LDAP_ERROR_PATTERNS: tuple[str, ...] = (
    r"javax\.naming\.(?:directory|naming)\.\w*exception",
    r"ldapexception|invalid dn syntax|ldap_search\(\)",
    r"system\.directoryservices\.directoryservicescomexception",
    r"ldap: error code \d+",
)

# An XML parser that tried to resolve an external entity. A rejection ("disallowed")
# is the safe outcome and is deliberately not in this list.
XXE_RESOLVED_PATTERNS: tuple[str, ...] = (
    r"failed to load external entity",
    r"xml external entity",
    r"simplexml_load_(?:string|file)\(\)",
    r"org\.xml\.sax\.(?:SAXParseException).{0,80}entity",
)

# Error text an XML/XPath engine surfaces when an expression was built by concatenating input.
XPATH_ERROR_PATTERNS: tuple[str, ...] = (
    r"xpathexception|xpath syntax error|invalid xpath expression",
    r"system\.xml\.xpath\.xpathexception",
    r"org\.w3c\.dom\.domexception",
    r"libxml.{0,20}xpath",
)

# A template expression's delimiter and the two small integers inside it (e.g. "{{7*7}}",
# "${7*7}", "#{7*7}", "<%= 7*7 %>", "@(7*7)") - the common SSTI probe shape across Jinja2,
# FreeMarker, Velocity, ERB and Thymeleaf-style engines.
TEMPLATE_EXPRESSION_PATTERN = r"(?:\{\{|\$\{|\#\{|<%=\s*|@\()\s*(\d{1,3})\s*\*\s*(\d{1,3})\s*(?:\}\}|\}|\s*%>|\))"

# An absolute, off-origin URL - what an open-redirect probe supplies as the parameter value.
ABSOLUTE_URL_PATTERN = r"^(?:https?:)?//"

# Tolerances ("materially equivalent" and divergence). Documented constants, not tuning knobs
# scattered through the code; callers may pass their own through DetectionContext.
BODY_LENGTH_TOLERANCE = 0.10  # relative difference still counted as the same size
BODY_LENGTH_TOLERANCE_FLOOR = 32  # bytes: differences below this are never material
JSON_KEY_OVERLAP_MIN = 0.80  # shared top-level keys needed to call two JSON bodies the same shape
DEFAULT_TIME_THRESHOLD_MS = 3000.0  # extra latency that counts as a delay
MIN_TIMING_SAMPLES = 2  # one slow request is noise
MAX_EXCERPT_CHARS = 200  # how much matched text a signal's detail may quote

# Statuses an unauthorized caller is expected to receive; never an authorization-boundary crossing.
DENIED_STATUSES = frozenset({401, 403})
