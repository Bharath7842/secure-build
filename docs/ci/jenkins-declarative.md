# CI integration — Jenkins Declarative Pipeline

Jenkinsfile snippet using the [HTTP Request Plugin](https://plugins.jenkins.io/http_request/) (`httpRequest`). The same POST → poll → GET pattern works in any pipeline; this shows credential binding for the Bearer token.

## Prerequisites

- **HTTP Request Plugin** installed on the controller or agent.
- Jenkins credential (type **Secret text**) holding the API token, e.g. credential ID `sast-api-token`.
- Pipeline environment variable `SAST_API_URL` (global env, folder property, or `environment` block).
- `SAST_PROJECT_ID` — project UUID from a one-time `POST /projects` call (see [curl example](curl-example.md)).

## Jenkinsfile snippet

```groovy
pipeline {
  agent any

  environment {
    SAST_API_URL = 'https://sast.example.com'
    SAST_PROJECT_ID = 'your-project-uuid-here'
  }

  stages {
    stage('SAST scan gate') {
      steps {
        script {
          def commitSha = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
          def branch = env.BRANCH_NAME ?: env.GIT_BRANCH?.replaceFirst(/^origin\//, '') ?: 'main'

          // Bind Bearer token from Jenkins credentials (never hardcode)
          withCredentials([string(credentialsId: 'sast-api-token', variable: 'SAST_API_TOKEN')]) {

            // 1. Trigger scan
            def triggerResponse = httpRequest(
              httpMode: 'POST',
              url: "${env.SAST_API_URL}/scans",
              customHeaders: [
                [name: 'Authorization', value: "Bearer ${env.SAST_API_TOKEN}"],
                [name: 'Content-Type', value: 'application/json']
              ],
              requestBody: """{
                "project_id": "${env.SAST_PROJECT_ID}",
                "commit_sha": "${commitSha}",
                "branch": "${branch}",
                "metadata": {
                  "source": "jenkins",
                  "jenkins_build": "${env.BUILD_URL}"
                }
              }""",
              validResponseCodes: '202'
            )

            def triggerJson = readJSON text: triggerResponse.content
            def scanId = triggerJson.scan_id
            echo "Scan triggered: ${scanId} (status: ${triggerJson.status})"

            // 2. Poll status every 20s, overall timeout 30 minutes
            def finalStatus = null
            def finalMessage = ''
            timeout(time: 30, unit: 'MINUTES') {
              waitUntil {
                def statusResponse = httpRequest(
                  httpMode: 'GET',
                  url: "${env.SAST_API_URL}/scans/${scanId}/status",
                  customHeaders: [
                    [name: 'Authorization', value: "Bearer ${env.SAST_API_TOKEN}"]
                  ],
                  validResponseCodes: '200'
                )
                def statusJson = readJSON text: statusResponse.content
                finalStatus = statusJson.status
                finalMessage = statusJson.message ?: ''
                echo "Scan ${scanId}: ${finalStatus} (${statusJson.progress}%) ${finalMessage}"
                if (finalStatus in ['success', 'failed']) {
                  return true
                }
                sleep time: 20, unit: 'SECONDS'
                return false
              }
            }

            if (finalStatus == 'failed') {
              error("Scan engine failed: ${finalMessage ?: 'unknown error'}")
            }

            // 3. Fetch results and enforce gate (only when status == success)
            def resultsResponse = httpRequest(
              httpMode: 'GET',
              url: "${env.SAST_API_URL}/scans/${scanId}/results",
              customHeaders: [
                [name: 'Authorization', value: "Bearer ${env.SAST_API_TOKEN}"]
              ],
              validResponseCodes: '200'
            )
            def results = readJSON text: resultsResponse.content
            def gate = results.gate_summary

            echo "Vulnerabilities found: ${gate.vulnerabilities_found}"
            echo "By severity: ${gate.by_severity}"

            if (gate.gate_failed) {
              error("Security gate failed: ${gate.gate_reason ?: 'threshold exceeded'}")
            }
          }
        }
      }
    }
  }
}
```

## Credential binding pattern

| Jenkins item | Purpose |
|--------------|---------|
| Secret text credential `sast-api-token` | API Bearer token → `SAST_API_TOKEN` via `withCredentials` |
| Env var `SAST_API_URL` | API base URL (no trailing slash) |
| Env var `SAST_PROJECT_ID` | Target project UUID |

Create the credential under **Manage Jenkins → Credentials**, then reference its ID in `credentialsId`. The token is never written to the Jenkinsfile or build log when bound this way.

## Notes

- `POST /scans` returns **202** with `{ scan_id, status, status_url }`. Re-posting the same `project_id` + `commit_sha` returns the existing scan unless `"force": true`.
- `GET /scans/{id}/results` returns **409** while the scan is `queued` or `running`; poll `/status` first.
- A scan with `status == "failed"` means the engine itself errored (checkout failure, agent crash, etc.) — fail the build immediately using the `message` field, before checking `gate_summary`.
- On security gate failure, `error(...)` marks the stage (and build) as failed. Alternatively use `currentBuild.result = 'FAILURE'` before `error` if you need custom post-build behavior.
