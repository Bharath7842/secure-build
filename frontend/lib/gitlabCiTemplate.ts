/**
 * The GitLab CI template the in-app guide (/projects/[id]/ci) hands out: a
 * shared `.secure-build-scan` job plus one job per scan type the project has
 * enabled. Scan only: the job starts a Secure Build scan of the pipeline's
 * commit, waits for it and saves the findings and reports as artifacts. It
 * fails only when the scan itself fails or times out; there is no findings gate.
 */

export type ScanType = "sast" | "sca" | "sbom";

export interface GitlabCiOptions {
  scanTypes: ScanType[];
  /** SB_WEB_URL: this web app's base URL, for the scan link in artifacts. */
  webUrl: string;
}

const SCRIPT_BLOCK = `  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      set -eu
      : "\${SAST_API_URL:?Set the Secure Build backend URL in GitLab CI/CD variables}"
      : "\${SAST_API_TOKEN:?Set the Secure Build CI bearer token}"
      : "\${SAST_PROJECT_ID:?Set the matching Secure Build project ID}"
      : "\${SB_SCAN_TYPE:?Set SB_SCAN_TYPE on the job}"
      : "\${CI_COMMIT_SHA:?Missing GitLab commit SHA}"
      : "\${CI_COMMIT_BRANCH:?This job requires a branch pipeline}"
      SAST_API_URL="\${SAST_API_URL%/}"

      case "$SB_SCAN_TYPE" in sast|sca|sbom) ;; *) echo "SB_SCAN_TYPE must be sast, sca or sbom" >&2; exit 1 ;; esac
      for value in "$SB_TIMEOUT_SECONDS" "$SB_POLL_SECONDS"; do
        case "$value" in ''|*[!0-9]*) echo "SB_TIMEOUT_SECONDS and SB_POLL_SECONDS must be positive integers" >&2; exit 1 ;; esac
      done
      [ "$SB_TIMEOUT_SECONDS" -gt 0 ] && [ "$SB_POLL_SECONDS" -gt 0 ]
      case "$SB_USE_LLM" in true|false) ;; *) echo "SB_USE_LLM must be true or false" >&2; exit 1 ;; esac
      LABEL="$(echo "$SB_SCAN_TYPE" | tr '[:lower:]' '[:upper:]')"
      OUT="\${SB_SCAN_TYPE}-artifacts"
      mkdir -p "$OUT"

      api() {
        # ngrok-skip-browser-warning avoids ngrok's free-tier interstitial page.
        curl --silent --show-error --fail --connect-timeout 10 --max-time 60 \\
          --header "ngrok-skip-browser-warning: 1" \\
          --header "Authorization: Bearer \${SAST_API_TOKEN}" "$@"
      }

      # The backend clones the repository configured on SAST_PROJECT_ID.
      # Never send CI_REPOSITORY_URL: it can contain GitLab job credentials.
      jq -n \\
        --arg project "$SAST_PROJECT_ID" --arg commit "$CI_COMMIT_SHA" \\
        --arg branch "$CI_COMMIT_BRANCH" --arg pipeline "$CI_PIPELINE_URL" \\
        --arg scan_type "$SB_SCAN_TYPE" --argjson use_llm "$SB_USE_LLM" \\
        '{project_id:$project, scan_type:$scan_type, use_llm:$use_llm, force:true,
          commit_sha:$commit, branch:$branch,
          metadata:{source:"gitlab", pipeline_url:$pipeline}}' > "$OUT/request.json"

      # Do not automatically retry POST: the first request may have started a scan.
      api --request POST --header "Content-Type: application/json" \\
        --data-binary @"$OUT/request.json" "$SAST_API_URL/scans" \\
        --output "$OUT/trigger.json"
      SCAN_ID="$(jq -er '.scan_id | select(type == "string" and test("^[A-Za-z0-9_-]+$"))' "$OUT/trigger.json")"
      echo "Secure Build $LABEL scan: $SCAN_ID"

      # Link to the scan in the Secure Build web app, saved before polling so it is
      # kept even if the scan fails or times out.
      SCAN_URL="\${SB_WEB_URL%/}/scans/$SCAN_ID"
      echo "Secure Build $LABEL scan page: $SCAN_URL"
      printf '%s\\n' "$SCAN_URL" > "$OUT/scan-url.txt"
      printf '<!doctype html><meta charset="utf-8"><title>Secure Build %s scan</title><p>Secure Build %s scan for commit %s: <a href="%s">%s</a></p>\\n' \\
        "$LABEL" "$LABEL" "$CI_COMMIT_SHORT_SHA" "$SCAN_URL" "$SCAN_URL" > "$OUT/secure-build-scan.html"

      DEADLINE=$(( $(date +%s) + SB_TIMEOUT_SECONDS ))
      while :; do
        if [ "$(date +%s)" -ge "$DEADLINE" ]; then
          echo "Timed out waiting for scan $SCAN_ID; check it in Secure Build." >&2
          exit 1
        fi
        api "$SAST_API_URL/scans/$SCAN_ID/status" --output "$OUT/status.json"
        STATUS="$(jq -er '.status | select(type == "string")' "$OUT/status.json")"
        echo "Scan $SCAN_ID: $STATUS"
        case "$STATUS" in
          success) break ;;
          queued|running|paused) sleep "$SB_POLL_SECONDS" ;;
          failed|cancelled|canceled)
            echo "Scan did not complete successfully; see Secure Build and status.json." >&2
            exit 1 ;;
          *) echo "Unexpected scan status: $STATUS" >&2; exit 1 ;;
        esac
      done

      api "$SAST_API_URL/scans/$SCAN_ID/findings" --output "$OUT/findings.json" \\
        || echo "Warning: could not download findings for scan $SCAN_ID." >&2

      # Reports for download from job artifacts; a failed export warns but does not fail the job.
      for fmt in $SB_EXPORTS; do
        case "$fmt" in pdf|xlsx|sarif|junit) ;; *) echo "Unknown export format: $fmt" >&2; exit 1 ;; esac
        api --max-time 180 "$SAST_API_URL/scans/$SCAN_ID/export.$fmt" \\
          --output "$OUT/secure-build-$SB_SCAN_TYPE-report.$fmt" \\
          || echo "Warning: could not download the $fmt report for scan $SCAN_ID." >&2
      done

      echo "$LABEL scan finished. Review the results in Secure Build: $SCAN_URL"
`;

const JOB_COMMENTS: Record<ScanType, string> = {
  sast: "# Source code scan.",
  sca: "# Dependency CVE scan.",
  sbom: "# Software bill of materials.",
};

export function buildGitlabCiYaml({ scanTypes, webUrl }: GitlabCiOptions): string {
  const types = scanTypes.length ? scanTypes : (["sast"] as ScanType[]);
  const lines = [
    "# Secure Build scans. Add these CI/CD variables in GitLab",
    "# (Settings -> CI/CD -> Variables):",
    "#   SAST_API_URL    public URL of the Secure Build backend",
    "#   SAST_API_TOKEN  Secure Build CI token (masked)",
    "#   SAST_PROJECT_ID Secure Build project ID for this repository",
    ".secure-build-scan:",
    "  stage: test",
    "  image: alpine:3.22",
    "  timeout: 40m",
    "  # Cancelling the job does not stop the backend scan, so don't auto-cancel it.",
    "  interruptible: false",
    "  # Scans of one Secure Build project share a backend workspace: run them one at a time.",
    "  resource_group: secure-build",
    "  # Runs on branch pipelines and scans the full repository at this commit.",
    "  rules:",
    "    - if: '$CI_COMMIT_BRANCH'",
    "  variables:",
    "    GIT_STRATEGY: none",
    '    SB_TIMEOUT_SECONDS: "1800"',
    '    SB_POLL_SECONDS: "20"',
    '    SB_USE_LLM: "false"',
    "    # Reports to save as job artifacts: any of pdf xlsx sarif junit.",
    '    SB_EXPORTS: "pdf"',
    "    # Secure Build web app, for the scan link saved in artifacts.",
    `    SB_WEB_URL: ${JSON.stringify(webUrl || "http://localhost:3000")}`,
    SCRIPT_BLOCK.replace(/\n$/, ""),
    "  artifacts:",
    '    name: "secure-build-$SB_SCAN_TYPE-$CI_COMMIT_SHORT_SHA"',
    "    when: always",
    "    access: developer",
    "    expire_in: 30 days",
  ];
  for (const type of types) {
    lines.push(
      "",
      JOB_COMMENTS[type],
      `secure-build-${type}:`,
      "  extends: .secure-build-scan",
      "  variables:",
      `    SB_SCAN_TYPE: ${type}`,
      ...(type === "sbom" ? ['    SB_EXPORTS: "pdf xlsx"'] : []),
      "  artifacts:",
      "    paths:",
      `      - ${type}-artifacts/`,
    );
  }
  return lines.join("\n") + "\n";
}
