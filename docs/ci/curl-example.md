# CI integration — curl example

Generic bash script for any CI pipeline. Secure Build exposes a REST API behind `Authorization: Bearer <token>`.

**Base URL:** set `SAST_API_URL` (e.g. `https://sast.example.com`) and `SAST_API_TOKEN` in your CI environment.

**Token scope:** `SAST_API_TOKEN` is the CI credential. It can create projects, start scans (including DAST), poll them and read results and exports; it cannot manage users, change settings or delete scans. People use their own accounts in the web app. Scans started with it show as CI scans with no owner, so in the web app only admins (and users allowed *View all scans*) see them.

**Prerequisite:** [`jq`](https://jqlang.github.io/jq/) must be installed for JSON parsing (`apt install jq`, `brew install jq`, etc.).

## One-time project setup

Create a project once per repository (or reuse an existing `project_id`):

```bash
curl -sS -X POST "${SAST_API_URL}/projects" \
  -H "Authorization: Bearer ${SAST_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-app",
    "description": "Spring Boot API scanned from CI",
    "languages": ["java"],
    "frameworks": ["spring-boot"],
    "build_tool": "maven",
    "default_git_url": "https://github.com/acme/my-app.git",
    "default_branch": "main",
    "enable_sast": true,
    "enable_sca": true,
    "scan_mode": "incremental",
    "max_files_to_scan": 40,
    "owasp_mode": "top10"
  }'
```

The response includes an `id` field — save it as `SAST_PROJECT_ID` for scan triggers.

## Complete scan gate script

Copy this into a CI job step. It triggers a scan for the current commit, polls until completion, fails immediately if the scan engine errors (`status == "failed"`), and only then checks the security gate on success.

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${SAST_API_URL:?Set SAST_API_URL}"
: "${SAST_API_TOKEN:?Set SAST_API_TOKEN}"
: "${SAST_PROJECT_ID:?Set SAST_PROJECT_ID}"

COMMIT_SHA="$(git rev-parse HEAD)"
BRANCH="${CI_BRANCH:-${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD)}}"

# 1. Trigger scan (202 Accepted; idempotent for same project_id + commit_sha)
TRIGGER_RESPONSE="$(
  curl -sS -X POST "${SAST_API_URL}/scans" \
    -H "Authorization: Bearer ${SAST_API_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
      \"project_id\": \"${SAST_PROJECT_ID}\",
      \"commit_sha\": \"${COMMIT_SHA}\",
      \"branch\": \"${BRANCH}\",
      \"metadata\": {
        \"source\": \"jenkins\",
        \"pipeline\": \"${CI_PIPELINE_ID:-local}\",
        \"build_url\": \"${CI_BUILD_URL:-}\"
      }
    }"
)"

SCAN_ID="$(echo "${TRIGGER_RESPONSE}" | jq -r '.scan_id')"
if [[ -z "${SCAN_ID}" || "${SCAN_ID}" == "null" ]]; then
  echo "Failed to trigger scan: ${TRIGGER_RESPONSE}" >&2
  exit 1
fi
echo "Scan triggered: ${SCAN_ID}"

# 2. Poll status every 20s, timeout after 30 minutes
POLL_INTERVAL=20
TIMEOUT_SECONDS=$((30 * 60))
DEADLINE=$((SECONDS + TIMEOUT_SECONDS))
STATUS=""

while [[ "${SECONDS}" -lt "${DEADLINE}" ]]; do
  STATUS_RESPONSE="$(
    curl -sS "${SAST_API_URL}/scans/${SCAN_ID}/status" \
      -H "Authorization: Bearer ${SAST_API_TOKEN}"
  )"
  STATUS="$(echo "${STATUS_RESPONSE}" | jq -r '.status')"
  PROGRESS="$(echo "${STATUS_RESPONSE}" | jq -r '.progress')"
  MESSAGE="$(echo "${STATUS_RESPONSE}" | jq -r '.message // empty')"

  echo "Scan ${SCAN_ID}: status=${STATUS} progress=${PROGRESS}% ${MESSAGE}"

  if [[ "${STATUS}" == "success" || "${STATUS}" == "failed" ]]; then
    break
  fi

  sleep "${POLL_INTERVAL}"
done

if [[ "${STATUS}" != "success" && "${STATUS}" != "failed" ]]; then
  echo "Scan timed out after ${TIMEOUT_SECONDS}s (last status: ${STATUS:-unknown})" >&2
  exit 1
fi

if [[ "${STATUS}" == "failed" ]]; then
  echo "Scan engine failed: ${MESSAGE:-unknown error}" >&2
  exit 1
fi

# 3. Fetch results (409 while queued/running; only reached when status == success)
RESULTS="$(
  curl -sS "${SAST_API_URL}/scans/${SCAN_ID}/results" \
    -H "Authorization: Bearer ${SAST_API_TOKEN}"
)"

GATE_FAILED="$(echo "${RESULTS}" | jq -r '.gate_summary.gate_failed')"
GATE_REASON="$(echo "${RESULTS}" | jq -r '.gate_summary.gate_reason // empty')"
VULNS="$(echo "${RESULTS}" | jq -r '.gate_summary.vulnerabilities_found')"

echo "Findings: ${VULNS}"
echo "${RESULTS}" | jq '.gate_summary.by_severity'

if [[ "${GATE_FAILED}" == "true" ]]; then
  echo "Security gate failed: ${GATE_REASON}" >&2
  exit 1
fi

echo "Security gate passed."
```

## API reference (fields used above)

| Step | Method | Path | Key response fields |
|------|--------|------|---------------------|
| Create project | `POST` | `/projects` | `id` |
| Trigger scan | `POST` | `/scans` | `scan_id`, `status`, `status_url` |
| Poll | `GET` | `/scans/{id}/status` | `status` (`queued` \| `running` \| `success` \| `failed`), `progress`, `message` |
| Results | `GET` | `/scans/{id}/results` | `gate_summary.gate_failed`, `gate_summary.gate_reason`, `gate_summary.vulnerabilities_found`, `gate_summary.by_severity`, `findings` |

Re-trigger the same commit without re-scanning by omitting `force` (default). Pass `"force": true` in the scan body to queue a new scan anyway.

A scan with `status == "failed"` indicates an engine error (checkout failure, agent crash, etc.) — fail the build using `message` before evaluating `gate_summary`. Only `status == "success"` should proceed to the security gate check.
