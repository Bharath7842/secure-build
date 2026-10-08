# Accessibility and states checklist (DAST-14-040)

Written for: whoever does the manual keyboard and screen-reader pass before release.

Scope: the DAST scan form, scan list, scan detail (counters, narration, discovery, analysis, findings, authorization matrix, report) and `/dast/settings`. The frontend has no test runner, so the items marked **Auto** were checked by reading the code and by `tsc`, `eslint` and `next build`. The items marked **Manual** need a person with a browser and have not been done.

## Fixed in this pass

| # | Defect | Fix |
|---|---|---|
| A1 | Typing dots and the message fade-in ignored `prefers-reduced-motion` | Both are switched off under that preference (`globals.css`) |
| A2 | Failure reason was one line of red text among other notices | Own `role="alert"` block headed "The scan failed" |
| A3 | Narration updates were not announced | The narration container is `role="log"` with `aria-live="polite"` |
| A4 | Buttons in the narration disclosure had no visible focus ring | Focus ring class added |
| A5 | Tables of pages and endpoints had no column scope | `scope="col"` on every header cell of the new panels |
| A6 | A custom-rule validation result changed without being announced | The result area is `aria-live="polite"` and linked to the editor with `aria-describedby` |

## Checks (Auto = done by reading and tooling, Manual = needs a person)

| Check | Result |
|---|---|
| Every control has a text label or `aria-label` (icon-only buttons, selects in tables, checkboxes in tables) | Auto: pass |
| Severity and verdict are never conveyed by colour alone (each chip carries its word) | Auto: pass |
| Matrix cells state role pair and result in their label; the diagonal says "not applicable" | Auto: pass |
| Confirmation before every destructive or risky action: stop scan, turn safe mode off, turn a check off, delete a custom rule, reset project rules | Auto: pass |
| Loading, empty, error and success states for each panel (counters, findings, matrix, report, rules, models, settings) | Auto: pass; every panel shows its own message instead of a blank area |
| Live regions announce status and errors (`role="status"` / `role="alert"`) | Auto: pass |
| Form errors name the field (server `errors[].field` is shown) | Auto: pass |
| Keyboard: tab order follows reading order, no trap in the side panel or confirm dialog, Escape closes dialogs | **Manual** |
| Screen reader: narration log, counters region, matrix, and rule table are understandable with VoiceOver and NVDA | **Manual** |
| Colour contrast of the muted text on the tinted chips at the app's real theme | **Manual** (use a contrast tool; `--muted` on `bg-amber-50` and `bg-slate-50` are the ones to check) |
| 200% zoom and a 360 px wide window: no horizontal page scroll (the rule and model tables scroll inside their own container by design) | **Manual** |

## Known gap

The shared confirm dialog (`ConfirmDialog.tsx`) is older code and was not changed: it has `role="dialog"` and `aria-modal` but does not move focus into the dialog or restore it on close. Fixing that benefits every page that uses it and is worth its own change.
