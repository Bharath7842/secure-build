# Rule catalog

Deterministic regex patterns, split by language. Loaded by
`pipeline/regex_scan.py:load_rules`, which reads **every `*.json` in this
directory except `surfaces.json`** and fails loudly on a duplicate rule id.

| File | Holds |
|---|---|
| `common.json` | language-agnostic (secrets, JWT) and cross-language rules |
| `java.json` | Java, including JSP (`.jsp` maps to the `java` language tag) |
| `xml.json` | deployment descriptors, `pom.xml`, SOAP/servlet config |
| `typescript.json` | TypeScript / JavaScript, Angular and React |
| `python.json` | Python |
| `web.json` | HTML and `.properties` / `.yaml` / `.env` |
| `iac.json` | Dockerfile (`dockerfile`), GitHub Actions workflows (`github-actions`, which also runs `yaml` rules) and CloudFormation templates (`yaml`, matched on CFN-specific keys). Languages come from `lang_for_path`, which tags `Dockerfile*` / `*.dockerfile` and `.github/workflows/*.yml` by name |
| `frontend-templates.json` | template markup shared by Angular `.html`, Vue `.vue` and JSX (`[innerHTML]`, `v-html`, `target="_blank"`) |
| `surfaces.json` | the stack → surface → rules map (not a rule file) |

Adding a language is just adding a file — `csharp.json`, `go.json` and friends
drop straight in, since the loader keys off the directory rather than a list of
filenames.

## What these patterns gate

Findings come from two passes (`pipeline/llm_file_scan.py`):

- **The top `DEEP_SCAN_FILE_CAP` (100) CRITICAL / HIGH files, by priority** —
  the LLM scans the whole file. These patterns are only *prompt guidance*
  there (title/cwe/severity/owasp; the regex itself is never sent), and they
  never gate: every file that makes it into this tier is scanned whether or
  not a pattern would match.
- **MEDIUM / LOW, plus any CRITICAL/HIGH file beyond the cap** — these patterns
  are the *entire* analysis. In the default `regex_only` triage mode no LLM
  looks at this tier at all: a file with no hit is skipped, and every hit is
  published verbatim as a finding with `verdict=unverified`. A CRITICAL/HIGH
  file routed here keeps its true risk_level for reporting, but is scanned
  exactly like a MEDIUM/LOW file. (Under the `llm_triage` mode the hits plus a
  ±10-line window each go to the LLM for a TP/FP ruling instead.)

So at this tier the catalog sets both bounds. A missing pattern is a missed
finding — for MEDIUM/LOW always, and for CRITICAL/HIGH files past the cap on a
large repo. An over-broad pattern is now worse than it used to be: with no LLM
triaging it away, every false hit is a row a human has to read. Prefer specific
patterns, and prefer no rule to a noisy one.

## Rule fields

```json
{
  "id": "java-printstacktrace",
  "title": "Stack trace printed instead of logged",
  "description": "Shown to the LLM as guidance; explain the risk and the fix.",
  "cwe": "CWE-209",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "category": "code | secrets | dependency",
  "owasp": "A09:2021-Security-Logging-and-Monitoring-Failures",
  "languages": ["java"],
  "frameworks": [],
  "requires_dependency": [],
  "pattern": "\\.printStackTrace\\s*\\(",
  "examples": {
    "match": ["e.printStackTrace();"],
    "no_match": ["log.error(\"failed\", e);"]
  }
}
```

`languages`, `frameworks`, and `requires_dependency` are three independent
filters, all **empty-means-universal** — an empty list never excludes anything.

- `languages` — tags from `llm_file_scan._EXT_TO_LANG`. Note `.jsp` → `java`,
  `.vue`/`.svelte` → `javascript`, and `.json` has **no** tag, so a rule meant
  to match `package.json` must leave `languages` empty and rely on a
  manifest-specific pattern. Template rules list
  `["html", "javascript", "typescript"]` so they reach Angular `.html`
  templates, Vue single-file components and inline templates alike.
- `frameworks` — must match a label from `pipeline/stack_signatures.py`
  exactly (e.g. `"Apache Struts (legacy MVC)"`, `"JBoss RESTEasy (JAX-RS)"`).
- `requires_dependency` — `[{"name": ..., "version_lt": ..., "version_lte": ...}]`,
  OR-ed. Matched against everything the manifests declare, not just
  signature-matched frameworks, so plain libraries work. `name` matches either
  the full coordinate (`org.apache.struts:struts-core`) or the bare artifact
  (`struts-core`).
- `severity` is what the rule tells the LLM (`render_catalog`) and what the engine
  logs; it is **not** the severity a stored finding shows. The app replaces it with
  the CVSS v3.1 band of the finding's CWE baseline (`backend/app/defaults/cwe_cvss.py`,
  `backend/app/services/severity.py`) and keeps it as `severity_basis.original_severity`.
  A rule with a new CWE needs a baseline there (`tests/test_severity.py` checks).
- `cvss_vector` (optional, e.g. `"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"`) —
  only for a rule whose pattern is clearly narrower than its CWE (an H2 console
  setting, a localhost URL); it replaces the CWE baseline for this rule's findings.
  It must hold for *every* match: a rule that also matches the CWE's worst case keeps
  the baseline.
- `group_by_rule` (default `false`) — how unverified findings from this rule
  collapse in the report/export and during grouped LLM confirmation. Default
  groups by `(rule_id, matched_text)`, so a hardcoded secret and a test
  placeholder that trip the same rule stay visibly separate rows. Set `true`
  when the matched text is *expected* to differ every time (a class name, a
  variable name) while still describing exactly one issue — e.g.
  `serializable-missing-svuid` matches `class Foo implements Serializable`,
  `class Bar implements Serializable`, ... and without this flag each class
  gets its own row instead of one row listing every affected class.
- `issue_class` (default `security`) — what kind of issue a hit is:
  `security`, `quality` (real behaviour, but no security boundary or impact is
  established — e.g. a missing `serialVersionUID`) or `inactive`. Copied onto
  the finding at hit time and stored as `Finding.issue_class`;
  `tests/test_rule_catalog.py` rejects any other value.
- `examples` — `{"match": [...], "no_match": [...]}`, each entry a code string
  or `{"code": ..., "path": "x.html"}` when the file extension should pick the
  language. Never read at scan time; `tests/test_rule_catalog.py` runs every
  example through the real scan path (line or multiline mode, comment
  masking, language/framework filter). **Every new rule must ship at least one
  `match` example** — put the look-alikes you deliberately don't flag in
  `no_match`.
- `scan_comments` (default `false`) — hits that start on a comment-only line
  are dropped, for line and multiline rules alike. Only a rule *about*
  comments (`entire-file-block-commented`) sets this.

Patterns containing `[\s\S]` are treated as whole-file searches and report
every match per file, up to `regex_scan.MULTILINE_HITS_PER_FILE_CAP` (25);
everything else runs line by line. Prefer a
zero-width lookahead (`(?!...)`) over a consuming quantifier for "assert X
doesn't follow within N chars" — a consuming match pulls that trailing text
into `matched_text`, which (absent `group_by_rule`) defeats grouping since the
trailing content varies per occurrence even when the actual issue doesn't.

### Derived wrapper rules

`runtime-sink-*` rules are not authored here: `derive_rules` builds them per scan from the call graph, one per *wrapper method* (owner + signature), with the id `runtime-sink-<kind>-<name>-<8 hex>` and the extra fields `wrapper_owner`, `wrapper_signature`, `wrapper_arity` and `tainted_params`. Their pattern stays the candidate matcher (`\bname\s*\(`); the `wrapper_call_identity` validator decides, per call, that it resolves to that wrapper. A SQL wrapper whose parameters never reach SQL text derives no rule.

### Pattern idioms

- **Not a log line.** Rules for concatenation (SQL, commands) start with a
  guard so logging the same string isn't reported:
  `^(?!\s*(?:[\w$]+\.)*(?:log|LOG|Log|logger|LOGGER|Logger|_log|_logger|logging)\s*\.|\s*System\.(?:out|err)\.|\s*throw\b)`.
  Then match the rest with a lazy `.*?`, and set `group_by_rule` because the
  matched text now includes the line prefix.
- **Not a constant.** Concatenating an ALL_CAPS constant isn't injection:
  `(?![A-Z][A-Z0-9_]*\b)[a-zA-Z_$][\w$]*`. This needs case-sensitive matching,
  so scope case-insensitivity to the keywords with `(?i:select|where)` rather
  than a leading `(?i)`.
- **Put `\s*` inside a negative lookahead**, never in front of it:
  `:(?!\s*['"])`, not `:\s*(?!['"])`. The regex engine backtracks the
  `\s*` to zero characters and then the lookahead sees a space and passes.
- **Bind a parameter to its use with a backreference**, and close the
  capture with `\b` so it can't backtrack to a prefix:
  `String\s+(\w+)\b(?=[\s\S]{0,600}?new\s+File\([^;]*?\b\1\b)`.

### Versions fail open

An absent or unparseable version (`null`, `${spring.version}`) makes the
condition **match**. A missing version must never be the thing that silently
disables a security rule — better a finding against an unknown version than a
hidden one. Comparison uses the leading numeric components and ignores
qualifiers, so `6.0.0.Final`, `1.3.10`, `^2.88.0` and `3.2` all compare sanely.

## `surfaces.json`

Encodes the reasoning the legacy audit docs in `../regex_data/` spell out by
hand for one project each:

```
Tech Stack Detected → Known Vulnerability Surface → Targeted Regex
```

```json
{
  "surface": "Deserialization gadget chain",
  "when": { "dependencies": [{ "name": "commons-collections", "version_lt": "3.2.2" }] },
  "rules": ["java-objectinputstream", "serializable-missing-svuid"],
  "rationale": "Serializable types only matter because a gadget-chain library is present"
}
```

`when` accepts `languages`, `frameworks`, and `dependencies`; every clause
present must be satisfied, and a surface with no clauses is always active.

**Surfaces never gate.** Execution is decided solely by `RegexRule.applies_to`,
so adding or mistyping a surface cannot drop coverage, and a rule named by no
surface still runs everywhere it applies. Surfaces do two things: narrate the
scan (one log line per active surface, reproducing the docs' reasoning for
whatever repo is being scanned) and sort matching rules to the front of the
prompt catalog so the 60-rule truncation keeps stack-relevant guidance.

## Absence checks belong to the LLM, not here

The source docs lean on checks like *no `@PreAuthorize`*, *missing
`X-Frame-Options`*, *`ActionForm` without `csrfPreventionSalt`*, *`Cookie`
without `setHttpOnly`*. **Do not add these as inverted regexes.** A regex
matches text that is present; "this file never calls X" is not expressible per
file, and the naive attempts produce either constant false positives or silent
false negatives.

Those checks belong to the CRITICAL/HIGH LLM pass, which reads the whole file
and can reason about what is missing — and auth, security, filter, and runtime
config files already land in those tiers under every stack profile.

## Ripgrep prefilter

The catalog is matched with Python `re` (`regex_scan.py`). The optional
ripgrep prefilter (`pipeline/rg_prefilter.py`) only searches for a fixed-string
literal extracted from each pattern's Python parse, and Python still decides
every hit. A rule pattern here therefore never has to be rg-compatible.

