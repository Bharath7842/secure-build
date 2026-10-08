# CI integration — GitHub Actions

Workflow snippet using `curl` and `jq` (no Jenkins plugins required). Store secrets and variables in the repository or organization settings.

## Prerequisites

| Setting | Type | Example |
|---------|------|---------|
| `SAST_API_TOKEN` | Repository or org **secret** | API Bearer token |
| `SAST_API_URL` | Repository or org **variable** (or secret) | `https://sast.example.com` |
| `SAST_PROJECT_ID` | Repository **variable** | Project UUID from `POST /projects` |

See [curl example](curl-example.md) for one-time project creation.

**Prerequisite:** [`jq`](https://jqlang.github.io/jq/) is preinstalled on `ubuntu-latest` runners; add an install step on other images if needed.

## Workflow snippet

Add this job (or merge the steps into an existing job after checkout):

```yaml
name: SAST gate

on:
  push:
    branches: [main]
  pull_request:

jobs:
  sast-scan:
    runs-on: ubuntu-latest
    env:
      SAST_API_URL: ${{ vars.SAST_API_URL }}
      SAST_PROJECT_ID: ${{ vars.SAST_PROJECT_ID }}
    steps:
      - uses: actions/checkout@v4

      - name: Trigger SAST scan
        id: trigger
        env:
          SAST_API_TOKEN: ${{ secrets.SAST_API_TOKEN }}
        run: |
          set -euo pipefail
          COMMIT_SHA="$(git rev-parse HEAD)"
          BRANCH="${GITHUB_REF_NAME}"

          RESPONSE="$(curl -sS -X POST "${SAST_API_URL}/scans" \
            -H "Authorization: Bearer ${SAST_API_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "{
              \"project_id\": \"${SAST_PROJECT_ID}\",
              \"commit_sha\": \"${COMMIT_SHA}\",
              \"branch\": \"${BRANCH}\",
              \"metadata\": {
                \"source\": \"jenkins\",
                \"github_run_id\": \"${GITHUB_RUN_ID}\",
                \"github_run_url\": \"${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}\"
              }
            }")"

          SCAN_ID="$(echo "${RESPONSE}" | jq -r '.scan_id')"
          if [[ -z "${SCAN_ID}" || "${SCAN_ID}" == "null" ]]; then
            echo "Failed to trigger scan: ${RESPONSE}" >&2
            exit 1
          fi
          echo "scan_id=${SCAN_ID}" >> "${GITHUB_OUTPUT}"
          echo "Triggered scan ${SCAN_ID}"

      - name: Wait for scan completion
        id: poll
        env:
          SAST_API_TOKEN: ${{ secrets.SAST_API_TOKEN }}
          SCAN_ID: ${{ steps.trigger.outputs.scan_id }}
        run: |
          set -euo pipefail
          POLL_INTERVAL=20
          TIMEOUT_SECONDS=$((30 * 60))
          DEADLINE=$((SECONDS + TIMEOUT_SECONDS))
          STATUS=""

          while [[ "${SECONDS}" -lt "${DEADLINE}" ]]; do
            RESPONSE="$(curl -sS "${SAST_API_URL}/scans/${SCAN_ID}/status" \
              -H "Authorization: Bearer ${SAST_API_TOKEN}")"
            STATUS="$(echo "${RESPONSE}" | jq -r '.status')"
            PROGRESS="$(echo "${RESPONSE}" | jq -r '.progress')"
            MESSAGE="$(echo "${RESPONSE}" | jq -r '.message // empty')"
            echo "Scan ${SCAN_ID}: status=${STATUS} progress=${PROGRESS}% ${MESSAGE}"

            if [[ "${STATUS}" == "success" || "${STATUS}" == "failed" ]]; then
              echo "status=${STATUS}" >> "${GITHUB_OUTPUT}"
              if [[ "${STATUS}" == "failed" ]]; then
                echo "Scan engine failed: ${MESSAGE:-unknown error}" >&2
                exit 1
              fi
              exit 0
            fi
            sleep "${POLL_INTERVAL}"
          done

          echo "Scan timed out after ${TIMEOUT_SECONDS}s" >&2
          exit 1

      - name: Enforce security gate
        env:
          SAST_API_TOKEN: ${{ secrets.SAST_API_TOKEN }}
          SCAN_ID: ${{ steps.trigger.outputs.scan_id }}
        run: |
          set -euo pipefail
          RESULTS="$(curl -sS "${SAST_API_URL}/scans/${SCAN_ID}/results" \
            -H "Authorization: Bearer ${SAST_API_TOKEN}")"

          echo "${RESULTS}" | jq '.gate_summary'

          GATE_FAILED="$(echo "${RESULTS}" | jq -r '.gate_summary.gate_failed')"
          if [[ "${GATE_FAILED}" == "true" ]]; then
            REASON="$(echo "${RESULTS}" | jq -r '.gate_summary.gate_reason // "threshold exceeded"')"
            echo "Security gate failed: ${REASON}" >&2
            exit 1
          fi
          echo "Security gate passed."
```

## Behavior

1. **Trigger** — `POST /scans` with `project_id`, `commit_sha`, and `branch`. Response: `{ scan_id, status, status_url }` (HTTP 202).
2. **Poll** — `GET /scans/{id}/status` every 20 seconds until `status` is `success` or `failed`, or 30 minutes elapse. If `status == "failed"`, print `message` and `exit 1` immediately (engine error, not a security finding).
3. **Gate** — only on success: `GET /scans/{id}/results`, check `gate_summary.gate_failed` with `jq`, `exit 1` on failure.

The scan trigger is idempotent per `project_id` + `commit_sha`; add `"force": true` to the JSON body to queue a fresh scan for the same commit.
