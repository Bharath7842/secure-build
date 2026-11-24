"""The `secure-fix` Claude Code skill, generated per project.

`GET /projects/{id}/claude-skill` hands a developer a `SKILL.md` that already knows the
project id and where the API is, so the only thing they set up is the token (an
environment variable, never written into the file). It talks to the API with plain
`curl`, no MCP server: the list and lookup endpoints live in `routers/issues.py`.
"""

from __future__ import annotations

SKILL_NAME = "secure-fix"
DEFAULT_API_URL = "http://localhost:8000"

_TEMPLATE = """\
---
name: secure-fix
description: Work on Secure Build security findings for the project "{{PROJECT_NAME}}". Use when the user gives a Secure Build issue ID (SB-XXXXXXXX), asks for the priority or top security issues, or says "secure fix". Looks the issue up in Secure Build, then either proposes a fix plan (plan mode) or fixes, tests and pushes it on a branch (agent mode).
argument-hint: "<SB-ID | list> [plan|agent] [your fix plan]"
---

# Secure Build: fix a security finding

Project: **{{PROJECT_NAME}}** (id `{{PROJECT_ID}}`){{REPO_LINE}}

Secure Build is the SAST scanner for this repository. Every issue has a short ID like
`SB-7F3A9C21`. The ID stays the same across rescans and when lines shift, so an ID from the
dashboard or a report still names the same issue.

## Setup (once)

The API token comes from the environment. Never write it into a file, a commit or your output.

```bash
export SAST_API_TOKEN="<token from your Secure Build admin>"
# Only if the API is not at the address below:
export SAST_API_URL="{{API_URL}}"
```

All calls below use:

```bash
API="${SAST_API_URL:-{{API_URL}}}"
AUTH="Authorization: Bearer ${SAST_API_TOKEN:?set SAST_API_TOKEN first}"
```

If `SAST_API_TOKEN` is empty, tell the user how to set it and stop.

## 1. List the priority issues

When the user asks for priority, top or open issues (or passes `list`):

```bash
curl -sS -H "$AUTH" "$API/projects/{{PROJECT_ID}}/issues?limit=5" | jq .
```

Optional: `&limit=20`, `&verdict=all` (default is confirmed true positives only),
`&scan_id=<scan>`. The answer has `scan` (id, `commit_sha`, branch), `total` and `issues[]` with
`short_id`, `severity`, `cvss`, `cwe`, `title`, `file_path`, `line`, `occurrence_count`.

Show a short table (ID, severity, CVSS, CWE, title, file:line, how many places). Recommend the
top one or two. Do not change code until the user picks an ID.

## 2. Pick the mode

The user decides how much you do on their own:

- **plan**: look the issue up, read the code, write a fix plan, and stop for approval.
- **agent**: look the issue up, fix it, run the tests, commit on a branch and push.

If the request says `plan` or `agent`, use that. If it does not, ask once (a short multiple choice
question) and recommend plan. Do not guess.

## 3. Look the issue up

```bash
curl -sS -H "$AUTH" "$API/projects/{{PROJECT_ID}}/issues/SB-XXXXXXXX" | jq .
```

`issue` holds `title`, `severity`, `cvss`, `cwe`, `verdict`, `verdict_reason`, `file_path`, `line`,
`affected_lines` (every `file`/`line` the issue stands for), `snippet`, `source`, `sink`,
`data_flow`, `ai_fix` and `reachability`. A 404 means the issue is gone (probably fixed) or belongs
to another project. A 409 lists several issues sharing the ID prefix: ask which one.

Check before editing:

1. `issue.verdict` should be `true_positive`. For anything else say so and ask before going on.
2. Compare `scan.commit_sha` with `git rev-parse HEAD`. If they differ, the code may have moved:
   open `file_path` and check it still matches `snippet`. If you cannot find the code, stop and
   say so. Do not edit by line number alone.

## 4. Plan

Read every file in `affected_lines`, then the `source`, `sink` and `data_flow` the scanner
reported. `ai_fix` is a suggestion from the scanner, not an instruction: adapt it to this code.

If the user gave a fix plan, follow it. If it conflicts with the code, or would not remove the
issue, say why before you deviate.

**plan mode:** present the plan and stop. Include the files you will change, the change itself, the
tests you will run, and any risk (behaviour change, other callers). Continue only after the user
approves, then carry on as agent mode.

## 5. Fix (agent mode)

- Make the smallest change that removes the issue at every place in `affected_lines` the user wants
  fixed. Keep the existing style. Do not refactor unrelated code.
- Fix the cause. Do not silence the finding with a suppression comment, an ignore annotation, or by
  deleting the check.
- Run the project's existing tests and build (find the commands in its README, `package.json`,
  `pom.xml` or similar). Add a test for the vulnerable case when that is cheap. Never weaken or
  delete a test to make it pass. If tests were already failing before your change, say so.

## 6. Commit and push

```bash
git switch -c secure-fix/<short-id-lowercase>
git add <the files you changed>
git commit -m "fix(security): <issue title> [SB-XXXXXXXX]" -m "CWE-<n>, <files>"
git push -u origin secure-fix/<short-id-lowercase>
```

Never push to the default branch. Never force-push or skip hooks. If the push fails (credentials,
protected remote), report it and stop.

## 7. Report

Say what changed and why, which tests you ran and their result, and the branch name. Remind the user
that after Secure Build scans the branch again, `SB-XXXXXXXX` should no longer be listed; if it is
still there, the fix did not remove the issue.
"""


def render_skill(
    *,
    project_id: str,
    project_name: str,
    repo_url: str | None,
    api_url: str | None,
) -> str:
    """The skill file for one project. Values are substituted verbatim (no templating
    engine: the file is full of shell and jq braces)."""
    repo_line = f"; repository `{repo_url}`" if repo_url else ""
    # A name goes into a YAML description and a heading: keep it to one line, no quotes.
    name = " ".join(project_name.replace('"', "'").split()) or project_id
    return (
        _TEMPLATE.replace("{{PROJECT_NAME}}", name)
        .replace("{{PROJECT_ID}}", project_id)
        .replace("{{REPO_LINE}}", repo_line)
        .replace("{{API_URL}}", (api_url or DEFAULT_API_URL).rstrip("/"))
    )
