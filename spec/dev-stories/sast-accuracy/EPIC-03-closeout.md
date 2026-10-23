# EPIC-03 close-out — SAST-03-090 (rescan, diff, adjudicate the 62 log and output findings)

Fill this in after the rescan. SAST-03-010 to 03-080 are merged; this is the only story left, and it needs a real scan. **Run it together with the EPIC-02 close-out (`EPIC-02-closeout.md`)**: both use the same checkout and both change the deep-scan prompt, so one cache-missing scan answers both tables.

## Before you scan

- [ ] **Do not scan with the Claude/Haiku (Bedrock) model.** Use the local Ollama provider (project settings: provider `ollama`, your local model). The previous accepted scan used a different model, so some differences in the diff come from the model, not from EPIC-03; note the model on every row you adjudicate.
- [ ] The app checkout is at `ae38067c239e`.
- [ ] Accuracy gate is green on the merge commit: `cd backend && python ../scripts/accuracy/gate.py --baseline tests/accuracy_corpus/accuracy_baseline.json --corpus tests/accuracy_corpus --out /tmp/gate`.
- [ ] Expect **one cache-missing scan**: `_SYSTEM_HEAD` changed once in this epic (SAST-03-060: log forging vs disclosure, parameterised logging is not a defence, stdout is not an XSS sink, Angular render context).
- [ ] Ask the project owner for the **logging configuration actually deployed** for npg-pakistan (a `logback.xml`/`log4j2.xml`, or the container's `standalone.xml` logging subsystem). The repository may not hold it; until it is supplied, every CWE-117 candidate carries a `log_layout_unknown` note. If it is supplied, put it in the checkout (for example `src/main/resources/logback.xml`) for a second scan and record the before/after counts below. No upload setting is built unless the owner supplies one.

## Run

1. `POST /scans` with `force: true` and `metadata.bypass_llm_cache: true`, branch/commit as above.
2. `GET /scans/{id}/decision-diff?base=<previous accepted scan id>` — save the JSON.
3. Export XLSX and PDF for the new scan; archive the exports, the diff and this table.
4. Join old and new rows with the SAST-00-080 labels file. `java-log-injection-unsanitized-input` now matches only the logger call itself (the pattern looks ahead instead of consuming), so its `matched_text` is shorter and group keys differ from the old scan: expect `fuzzy` joins, and resolve them by hand.
5. Check `usage_summary`:
   - `validators` by `reason_tag` (`log_source_outside_call`, `not_a_logger_call`, `log_arg_constrained`, `exception_message_constrained`, `external_text_possible`, `log_layout_neutralises`, `log_layout_raw`, `log_layout_unknown`, `xss_sink_not_http_response`, `xss_no_request_source`, `xss_arg_constrained`, `angular_text_interpolation`, `angular_sanitised_html`, `angular_unsafe_render`);
   - `exception_summaries` (`classes`, `variables`, `cache_hits`, `depth_exceeded`, `milliseconds`): summary time should stay under 5% of the scan's wall time;
   - the scan log line `Logging configuration: ...` (what was found in the repository);
   - `publish_filter` still drops nothing it should keep (CWE-117/532 are never dropped on a log line).

## Acceptance (all must hold)

- [ ] Every **supported** finding (call boundary, stdout-as-XSS, constrained value) is `false_positive` with the proof tag in the table.
- [ ] Every **conditional** finding (exception, layout, Angular) is `false_positive` with a proof, or `unverified` with a *named* gap. None is a bare true positive or an unexplained false positive.
- [ ] **Disputed** findings (#130, #197, #203, #204, #205, #206, #273) are never `false_positive`.
- [ ] **Preservation positives** still true positive: #257, #258, #270 (CWE-532, on `logger` and `System.out`) and the message-derived log findings #138, #194, #202, #207 (CWE-117), whether or not the layout is known.
- [ ] A CWE-117 proof never changed a CWE-532 finding on the same line (compare row pairs).
- [ ] Every `true_positive → false_positive` transition **outside** these 62 is listed below and reviewed by a second person.
- [ ] Every finding still `unverified` has its evidence named below (deployed log layout, exception constructor, template).
- [ ] Accuracy gate green; `adjudication` flipped to `adjudicated` only for corpus cases a second reviewer agreed with.

## The 62 findings

Outcome codes: **FP** = `false_positive` with the proof tag shown; **FP/GAP** = FP with proof, or `unverified` with a named gap; **never FP** = `true_positive` or `unverified`, never dismissed.

| # | Group | Expected | Likely proof / mechanism | Old verdict | New verdict | `reason_tag` / gap | Reviewer |
|---|---|---|---|---|---|---|---|
| 16 | value constraint | unverified + gap | request `Locale`: container Accept-Language parsing and Locale serialisation | | | | |
| 27 | Angular render context (conditional) | FP/GAP | `angular_text_interpolation` listing the template lines, or a named gap | | | | |
| 79 | Angular render context (conditional) | FP/GAP | `angular_text_interpolation` listing the template lines, or a named gap | | | | |
| 80 | Angular render context (conditional) | FP/GAP | `angular_text_interpolation` listing the template lines, or a named gap | | | | |
| 81 | exception provenance (conditional) | FP/GAP | `exception_message_constrained`, or `exception_provenance_unknown` naming the types/methods | | | | |
| 83 | value constraint (conditional) | FP/GAP | project exception built only from literals (`exception_message_constrained`), or a named gap | | | | |
| 86 | exception provenance | FP | `exception_message_constrained` (`InterruptedException` from `Thread.sleep`) | | | | |
| 93 | call boundary (supported) | FP | `log_source_outside_call` (constant log line; the source is in the next `throw`) | | | | |
| 96 | call boundary (rethrow) | FP/GAP | a rethrow carries the source exception's domain (`exception_message_constrained`), or a named gap | | | | |
| 97 | call boundary (rethrow) | FP/GAP | a rethrow carries the source exception's domain (`exception_message_constrained`), or a named gap | | | | |
| 98 | call boundary (supported) | FP | `log_source_outside_call`; the adjacent call is judged on its own | | | | |
| 100 | exception provenance (conditional) | FP/GAP | `exception_message_constrained`, or `exception_provenance_unknown` naming the types/methods | | | | |
| 101 | call boundary | FP/GAP | `log_source_outside_call`, or a named gap | | | | |
| 103 | exception provenance (conditional) | FP/GAP | `exception_message_constrained`, or `exception_provenance_unknown` naming the types/methods | | | | |
| 108 | exception provenance (conditional) | FP/GAP | `exception_message_constrained`, or `exception_provenance_unknown` naming the types/methods | | | | |
| 109 | exception provenance (conditional) | FP/GAP | `exception_message_constrained`, or `exception_provenance_unknown` naming the types/methods | | | | |
| 110 | call boundary (rethrow) | FP/GAP | a rethrow carries the source exception's domain (`exception_message_constrained`), or a named gap | | | | |
| 111 | exception provenance (conditional) | FP/GAP | `exception_message_constrained`, or `exception_provenance_unknown` naming the types/methods | | | | |
| 115 | call boundary (supported) | FP | `log_source_outside_call` (constant log line; the source is in the next `throw`) | | | | |
| 116 | exception provenance (conditional) | FP/GAP | `exception_message_constrained`, or `exception_provenance_unknown` naming the types/methods | | | | |
| 117 | call boundary (supported) | FP | `log_source_outside_call` / `not_a_logger_call` | | | | |
| 118 | value constraint (supported) | FP | `log_arg_constrained` (count, parsed number actually used, `BigInteger` getter) | | | | |
| 119 | exception provenance (conditional) | FP/GAP | `exception_message_constrained`, or `exception_provenance_unknown` naming the types/methods | | | | |
| 120 | call boundary (supported) | FP | `log_source_outside_call` / `not_a_logger_call` | | | | |
| 126 | value constraint (conditional) | FP/GAP | project exception built only from literals (`exception_message_constrained`), or a named gap | | | | |
| 127 | call boundary (supported) | FP | `log_source_outside_call` / `not_a_logger_call` | | | | |
| 128 | value constraint (conditional) | FP/GAP | project exception built only from literals (`exception_message_constrained`), or a named gap | | | | |
| 129 | exception provenance | FP/GAP | VM-generated `NullPointerException` (counter-case: an explicit message is a positive candidate) | | | | |
| 130 | exception provenance (**disputed**) | never FP | `external_text_possible` (generic `Exception`, `SQLException`, `SAXParseException`, `SOAPFaultException`, ...) or a named gap; the layout then decides only the CWE-117 outcome | | | | |
| 132 | call boundary (supported) | FP | `log_source_outside_call` / `not_a_logger_call` | | | | |
| 133 | value constraint (supported) | FP | `log_arg_constrained` (count, parsed number actually used, `BigInteger` getter) | | | | |
| 134 | value constraint (conditional) | FP/GAP | project exception built only from literals (`exception_message_constrained`), or a named gap | | | | |
| 135 | call boundary (supported) | FP | `log_source_outside_call` / `not_a_logger_call` | | | | |
| 136 | value constraint (conditional) | FP/GAP | project exception built only from literals (`exception_message_constrained`), or a named gap | | | | |
| 137 | call boundary (supported) | FP | `log_source_outside_call` / `not_a_logger_call` | | | | |
| 139 | value constraint (conditional) | FP/GAP | project exception built only from literals (`exception_message_constrained`), or a named gap | | | | |
| 140 | call boundary (supported) | FP | `log_source_outside_call` / `not_a_logger_call` | | | | |
| 141 | exception provenance (conditional) | FP/GAP | `exception_message_constrained`, or `exception_provenance_unknown` naming the types/methods | | | | |
| 143 | call boundary (supported) | FP | `log_source_outside_call` (constant log line; the source is in the next `throw`) | | | | |
| 144 | call boundary (supported) | FP | `log_source_outside_call` (constant log line; the source is in the next `throw`) | | | | |
| 146 | value constraint (supported) | FP | `log_arg_constrained` (count, parsed number actually used, `BigInteger` getter) | | | | |
| 170 | value constraint (supported) | FP | `log_arg_constrained` (count, parsed number actually used, `BigInteger` getter) | | | | |
| 186 | call boundary (supported) | FP | `log_arg_constrained` (`static final` class-name constant) | | | | |
| 192 | exception provenance | FP/GAP | `StackOverflowError` is VM-generated unless constructed explicitly | | | | |
| 195 | value constraint (supported) | FP | `log_arg_constrained` (count, parsed number actually used, `BigInteger` getter) | | | | |
| 197 | exception provenance (**disputed**) | never FP | `external_text_possible` (generic `Exception`, `SQLException`, `SAXParseException`, `SOAPFaultException`, ...) or a named gap; the layout then decides only the CWE-117 outcome | | | | |
| 198 | call boundary (supported) | FP | `log_source_outside_call`; the adjacent call is judged on its own | | | | |
| 199 | call boundary (supported) | FP | `log_source_outside_call`; the adjacent call is judged on its own | | | | |
| 200 | call boundary (supported) | FP | `log_source_outside_call`; the adjacent call is judged on its own | | | | |
| 203 | exception provenance (**disputed**) | never FP | `external_text_possible` (generic `Exception`, `SQLException`, `SAXParseException`, `SOAPFaultException`, ...) or a named gap; the layout then decides only the CWE-117 outcome | | | | |
| 204 | exception provenance (**disputed**) | never FP | `external_text_possible` (generic `Exception`, `SQLException`, `SAXParseException`, `SOAPFaultException`, ...) or a named gap; the layout then decides only the CWE-117 outcome | | | | |
| 205 | exception provenance (**disputed**) | never FP | `external_text_possible` (generic `Exception`, `SQLException`, `SAXParseException`, `SOAPFaultException`, ...) or a named gap; the layout then decides only the CWE-117 outcome | | | | |
| 206 | exception provenance (**disputed**) | never FP | `external_text_possible` (generic `Exception`, `SQLException`, `SAXParseException`, `SOAPFaultException`, ...) or a named gap; the layout then decides only the CWE-117 outcome | | | | |
| 208 | Angular render context (conditional) | FP/GAP | `angular_text_interpolation` listing the template lines, or a named gap | | | | |
| 210 | Angular render context (conditional) | FP/GAP | CWE-94: `angular_no_evaluator` (a dictionary lookup is not code execution) | | | | |
| 211 | stdout reported as XSS (supported) | FP | `xss_sink_not_http_response` | | | | |
| 212 | stdout reported as XSS (supported) | FP | `xss_sink_not_http_response` | | | | |
| 213 | stdout reported as XSS (supported) | FP | `xss_sink_not_http_response` | | | | |
| 214 | stdout reported as XSS (supported) | FP | `xss_sink_not_http_response` | | | | |
| 215 | stdout reported as XSS (supported) | FP | `xss_sink_not_http_response` | | | | |
| 216 | stdout reported as XSS (supported) | FP | `xss_sink_not_http_response` | | | | |
| 273 | Angular render context (**disputed**) | never FP | the dynamic-key `else` branch is judged on its own consumers | | | | |

### Preservation positives

| Finding | Must stay | Old | New | OK? |
|---|---|---|---|---|
| #257 (credential in a logger call) | TP (CWE-532) | | | |
| #258 | TP (CWE-532) | | | |
| #270 (credential on `System.out`) | TP (CWE-532) | | | |
| #138 | TP (CWE-117) | | | |
| #194 | TP (CWE-117) | | | |
| #202 | TP (CWE-117) | | | |
| #207 | TP (CWE-117) | | | |

### `true_positive → false_positive` outside the 62 (second reviewer required)

| Finding (rule, file:line) | Proof tag | Why it is right | Reviewer | Label updated |
|---|---|---|---|---|
| | | | | |

### Logging configuration

| Scan | Config source | `log_layout_unknown` | `log_layout_raw` | `log_layout_neutralises` |
|---|---|---|---|---|
| Repository only | | | | |
| With the deployed config (if supplied) | | | | |

### Still `unverified`

| Finding | Named gap | Evidence that would resolve it |
|---|---|---|
| | | |

## Sign-off

- [ ] Close-out table reviewed by: ______  on: ______
- [ ] Labels file updated: ______
- [ ] Accuracy gate green on the final commit: ______
