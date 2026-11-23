# Add Secure Build scans to GitLab CI

**Easiest path: the in-app guide.** In Secure Build open **Projects → GitLab CI** on the project (`/projects/<project-id>/ci`). It shows the real values to copy into GitLab's CI/CD variables (`SAST_API_URL`, `SAST_API_TOKEN` for admins only, `SAST_PROJECT_ID`) and the `.gitlab-ci.yml` to commit. `SAST_API_URL` comes from the backend's `PUBLIC_API_URL` setting, or from a running ngrok tunnel to the backend port when that is unset. The YAML is built by `frontend/lib/gitlabCiTemplate.ts`.

The pipeline has a shared `.secure-build-scan` job and one job per scan type enabled on the project (SAST, SCA, SBOM). Each job starts a Secure Build scan of the pipeline's commit, waits for it and saves the findings and reports into `<type>-artifacts/`. **There is no findings gate for now:** a job fails only when the scan itself fails, times out or the API cannot be reached.

## 1. Prepare Secure Build

- Run the Secure Build backend with real scanning enabled (`USE_MOCK_ENGINE=false`, `RUN_LIVE_SAST=1`) and configure a working model provider.
- Create a Secure Build project for **the same GitLab repository** where this CI job will run. Set its repository URL and branch. Connect GitLab for private-repository access and verify a manual SAST scan works.
- Copy the project UUID from its URL: `/projects/<project-id>`.
- Obtain the backend's configured `SAST_API_TOKEN` from your Secure Build administrator. This is separate from a GitLab access token.
- Make the backend reachable from your **self-hosted runner**. `SAST_API_URL` must point to the FastAPI backend, not the frontend's `/api` proxy. Inside a Docker job, `localhost` means that job container.

The flow is: **GitLab job → Secure Build API → backend clones the selected commit → SAST analysis → findings → CI pass/fail**. The backend needs its own repository access; the runner's checkout credentials are not automatically available to it.

## 2. Add GitLab variables

In your GitLab application project, open **Settings → CI/CD → Variables** and add:

| Variable | Value | Setting |
| --- | --- | --- |
| `SAST_API_URL` | Backend URL, for example `https://secure-build-api.example.com` | Regular variable |
| `SAST_API_TOKEN` | Secure Build backend CI token | Masked and protected |
| `SAST_PROJECT_ID` | UUID of the matching Secure Build project | Regular variable |

For the existing **Expense Tracker - B** project, use `SAST_PROJECT_ID=d6c34304-96d2-44de-b431-52b8615ec570`. It maps to `https://gitlab.com/bhrthmahesh09/expense-tracker.git`, branch `main`. Use this ID only when adding the job to that repository.

Choose the backend address for your runner:

| Self-hosted runner location | `SAST_API_URL` |
| --- | --- |
| Shell executor on the Secure Build backend host | `http://127.0.0.1:8000` |
| Docker Desktop executor on the same Mac | `http://host.docker.internal:8000`, after verifying host routing and backend binding |
| Another machine on the same network | Your reachable internal backend hostname, preferably HTTPS |

The local Mac address observed during preparation was `192.168.0.8`. `http://192.168.0.8:8000` is usable only if the backend listens on a reachable interface and the runner can connect; this LAN route has not been verified and the address may change. The documentation preview backend listens on loopback only.

Test connectivity **from the runner job environment**, not just your browser:

```sh
curl --fail --silent --show-error "$SAST_API_URL/health"
```

The health response should report `status: ok`. A healthy endpoint does not validate the bearer token or repository access.

Use environment scope `*`. Protect every branch that should run the scan so the protected token is available there. The jobs run on **branch pipelines** (`if: $CI_COMMIT_BRANCH`), including pushes and manually started pipelines; they do not run in merge-request pipelines or for tags. See [GitLab variable settings](https://docs.gitlab.com/ci/variables/).

Optional settings are job variables in the YAML; a CI/CD variable of the same name overrides them:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SB_EXPORTS` | `pdf` (SBOM: `pdf xlsx`) | Reports saved as artifacts: any of `pdf xlsx sarif junit` |
| `SB_USE_LLM` | `false` | LLM review for SAST; SCA/SBOM never use the LLM |
| `SB_WEB_URL` | the Secure Build web app URL | Used for the scan link saved in `scan-url.txt` |
| `SB_TIMEOUT_SECONDS` / `SB_POLL_SECONDS` | `1800` / `20` | How long to wait, and how often to poll |

## 3. Add the YAML to the application repository

- If there is no pipeline file, save the generated YAML as `.gitlab-ci.yml` at the repository root.
- If a pipeline already exists, merge the `.secure-build-scan` and `secure-build-*` jobs into it. Preserve existing jobs and add `test` to your existing `stages` list if needed, or change this job's stage to one of yours before deployment.
- Use a Docker or Kubernetes runner that supports the Alpine image. If your runners require tags, add the appropriate `tags` to the job. A shell runner needs its own installed `curl` and `jq` and a suitable replacement for `before_script`.
- Validate the merged YAML with GitLab's pipeline editor / CI Lint, then commit it to the default branch. GitLab documents validation in its [YAML reference](https://docs.gitlab.com/ci/yaml/).

The job uses `force:true` to request a fresh assessment of the pipeline commit. It serializes jobs from this GitLab project to reduce conflicts against the shared backend workspace. Avoid simultaneous manual scans against the same Secure Build project while CI is using it.

For an **existing shell executor**, remove `image: alpine:3.22` and replace `before_script` with:

```yaml
  before_script:
    - command -v curl
    - command -v jq
```

The runner administrator must install these commands first. Set `tags` to an actual tag assigned to your runner under **Settings → CI/CD → Runners**. Do not invent a runner tag; omit tags only if the runner accepts untagged jobs.

## 4. Read the outcome

Open **Build → Pipelines**, select the pipeline, and open `secure-build-sast` (or `-sca` / `-sbom`).

| Outcome | Meaning |
| --- | --- |
| Passed | The scan completed; review its findings in Secure Build |
| Failed | Missing variables, API/network errors, scan failure, or timeout |

Download `sast-artifacts/` (or `sca-artifacts/` / `sbom-artifacts/`) for the scan link, reports, the scan ID, latest status and findings. Open the scan in Secure Build for detailed review. These files are ordinary job artifacts; this example does not configure GitLab's security dashboard ingestion.

To block deployment, put deployment after the scan stage and avoid `needs` or `when: always` settings that bypass the scan. A default-branch job checks code after it reaches that branch; it is not a pre-merge gate.

## Important implementation details

- This example uses `GET /scans/{id}/findings`. The current `GET /scans/{id}/results` returns discovery/usage metadata, **not** the `gate_summary` shown in older CI guides.
- A passing job means the scan completed, not that there are no findings: review them in Secure Build.
- Cancelling or timing out the GitLab job does not automatically cancel the backend scan. Use an authorized Secure Build account to stop it if necessary.
- A live pipeline run still requires your actual endpoint, token, project, runner, and repository access. This template was checked with mock API responses; no live GitLab scan was executed during documentation preparation.

## Common setup problems

| Problem | Check |
| --- | --- |
| Job absent | The jobs run only in branch pipelines; check existing `workflow` rules too |
| Job pending | Check runner availability and any required runner tags |
| Missing token | Verify the branch is protected and variable scope is `*` |
| HTTP 401/403 | Verify the backend CI token and permissions; do not use a GitLab token as `SAST_API_TOKEN` |
| HTTP 404 | Check the backend URL and Secure Build project ID |
| Connection refused/timeout | Check runner-to-backend routing, firewall, and TLS trust |
| Repository checkout failed | Check backend GitLab authentication and that the requested commit belongs to the configured repository |
| Model/preflight error | Verify the project's model settings and credentials on the Secure Build server |
