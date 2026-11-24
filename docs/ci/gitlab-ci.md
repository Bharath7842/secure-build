# Add Secure Build scans to GitLab CI

Two variables and one YAML file. Nothing is set up in the Secure Build app first: no project, no project ID, no "Connect GitLab".

The pipeline tells Secure Build which repository, branch and commit it is running for. Secure Build finds the project for that repository (creating it on the first scan), clones the commit, scans it and returns the results to the job. Supported scan types: **SAST, SCA and SBOM**.

**Easiest path: the in-app guide.** In Secure Build open **Projects → GitLab CI** (`/projects/<project-id>/ci`). It shows the values to paste into GitLab and the `.gitlab-ci.yml` to commit; the YAML is built by `frontend/lib/gitlabCiTemplate.ts`. `SAST_API_URL` comes from the backend's `PUBLIC_API_URL` setting, or from a running ngrok tunnel to the backend port when that is unset.

There is **no findings gate for now:** a job fails only when the scan itself fails, times out or the API cannot be reached.

## 1. What you need

| Where | What |
| --- | --- |
| GitLab repository | Two CI/CD variables (below) and the `.gitlab-ci.yml` jobs |
| GitLab repository (private repos only) | CI job token access allowed for the repository (below) |
| Secure Build backend | Real scanning on (`USE_MOCK_ENGINE=false`, `RUN_LIVE_SAST=1`) and a working model provider for SAST with LLM review; reachable from the runner; able to reach your GitLab host over HTTPS |

Nothing else. The repository URL, branch, commit and a short-lived access token all come from GitLab's built-in CI variables (`CI_PROJECT_URL`, `CI_COMMIT_BRANCH`, `CI_COMMIT_SHA`, `CI_JOB_TOKEN`).

## 2. Add GitLab variables

In the GitLab repository (or its group, to cover many repositories at once) open **Settings → CI/CD → Variables** and add:

| Variable | Value | Setting |
| --- | --- | --- |
| `SAST_API_URL` | Backend URL, for example `https://secure-build-api.example.com` | Regular variable |
| `SAST_API_TOKEN` | Secure Build backend CI token (ask your Secure Build administrator; it is not a GitLab token) | Masked. Leave "Protect variable" off, or protect every branch you scan |

`SAST_API_URL` must point to the FastAPI backend, not the frontend's `/api` proxy. Inside a Docker job `localhost` means the job container.

| Self-hosted runner location | `SAST_API_URL` |
| --- | --- |
| Shell executor on the Secure Build backend host | `http://127.0.0.1:8000` |
| Docker Desktop executor on the same Mac | `http://host.docker.internal:8000`, after verifying host routing and backend binding |
| Another machine on the same network | Your reachable internal backend hostname, preferably HTTPS |

Test connectivity **from the runner job environment**, not just your browser:

```sh
curl --fail --silent --show-error "$SAST_API_URL/health"
```

The response should report `status: ok`. A healthy endpoint does not validate the token or repository access.

### Private repositories: job token access

The backend clones with the pipeline's `CI_JOB_TOKEN`, which GitLab only honors if the repository allows it. In the repository open **Settings → CI/CD → Job token permissions** and make sure job token access is enabled (on newer GitLab versions, add the repository to the allowlist if it is restricted). Public repositories need nothing.

The token is short-lived (it stops working when the job ends) and Secure Build never stores it: it is sent in the request body only, kept in the backend's memory for that one scan, masked in scan logs, and removed from the checkout's git remote afterwards. The job's saved `request.json` artifact is written without it.

## 3. Add the YAML

- If there is no pipeline file, save the generated YAML as `.gitlab-ci.yml` at the repository root.
- If a pipeline already exists, merge the `.secure-build-scan` and `secure-build-*` jobs into it. Preserve existing jobs and add `test` to your `stages` if needed, or change the stage to one of yours.
- Use a Docker or Kubernetes runner that supports the Alpine image. Add `tags` if your runners require them. A shell runner needs its own `curl` (7.76 or newer) and `jq` and a replacement for `before_script`.
- Validate the merged YAML with GitLab's pipeline editor / CI Lint, then commit it.

The jobs run on **branch pipelines** (`if: $CI_COMMIT_BRANCH`); not on merge-request pipelines or tags. There is one job per scan type, sharing a `resource_group` so the scans of one repository run one at a time.

### Options (job variables in the YAML)

All optional; a CI/CD variable of the same name overrides them. They apply to that scan only: they never change a project's saved settings.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SB_USE_LLM` | `false` | LLM review for SAST; SCA/SBOM never use the LLM |
| `SB_LLM_PROVIDER` / `SB_LLM_MODEL` | empty (server default) | Model for this SAST scan |
| `SB_PATH` | empty (whole repo) | Subdirectory of a monorepo to scan |
| `SB_FORCE` | `false` | Scan a commit again instead of showing its earlier scan |
| `SB_EXPORTS` | `pdf` (SBOM: `pdf xlsx`) | Reports saved as artifacts: any of `pdf xlsx sarif junit` |
| `SB_WEB_URL` | the Secure Build web app URL | Used for the scan link saved in `scan-url.txt` |
| `SB_TIMEOUT_SECONDS` / `SB_POLL_SECONDS` | `1800` / `20` | How long to wait, and how often to poll |

## 4. What happens on each run

```
GitLab job -> POST /ci/scan (repo URL, branch, commit, job token)
           -> find the project for that URL, or create it       (first scan only)
           -> scan already exists for this commit?  yes: return it    no: clone/fetch and scan
           -> job polls the scan, then saves findings and reports as artifacts
```

- **First scan of a repository:** Secure Build creates a project named after the repository path (for example `group/repo`), described as created from a CI pipeline, with the default settings. It appears under Projects like any other, and you can open it to review results.
- **Next scans:** the same project is found by repository URL. Spelling does not matter: `.git`, a trailing slash, upper case or an `ssh` style `git@host:group/repo.git` all name one repository, and so does a project you created by hand in the app. Each new commit is the next scan **version** of the project; the workspace is fetched, not cloned again, and unchanged work is served from the LLM result cache.
- **Same commit again** (a pipeline re-run, or SAST, SCA and SBOM jobs for one commit): the earlier scan of that commit and scan type is returned (`reused: true`) with no new work. Set `SB_FORCE=true` for a fresh scan.
- **Branches** are a parameter of each scan, not separate projects: every branch of a repository shares one project and one version history.
- **Concurrent pipelines** of one repository take turns on the backend (they share one checkout); a scan waiting its turn stays `queued`.

## 5. Read the outcome

Open **Build → Pipelines**, select the pipeline, and open `secure-build-sast` (or `-sca` / `-sbom`).

| Outcome | Meaning |
| --- | --- |
| Passed | The scan completed; review its findings in Secure Build |
| Failed | Missing variables, API/network errors, scan failure, or timeout. The job prints the API's error message |

Download `sast-artifacts/` (or `sca-artifacts/` / `sbom-artifacts/`) for the scan link, reports, the scan ID, latest status and findings. A passing job means the scan completed, not that there are no findings. These files are ordinary job artifacts; this example does not configure GitLab's security dashboard ingestion.

## The API

`POST /ci/scan` (CI bearer token) is what the job calls; you can use it from any CI system.

```json
{
  "repo_url": "https://gitlab.example.com/group/repo.git",
  "branch": "main",
  "commit_sha": "<sha>",
  "job_token": "<CI_JOB_TOKEN, private repos only>",
  "scan_types": ["sast", "sca", "sbom"],
  "use_llm": false,
  "llm_provider": null,
  "llm_model": null,
  "path": null,
  "force": false,
  "metadata": {"pipeline_url": "…"}
}
```

Only `repo_url` is required. The response lists `project_id`, `project_created` and one entry per scan type (`scan_id`, `status`, `status_url`, `scan_url`, `version`, `reused`). A project created in the app with a scan type switched off answers `400` naming it; enable it in the project's settings or drop it from `scan_types`. Poll `GET /scans/{id}/status`, then `GET /scans/{id}/findings` as before.

## Common setup problems

| Problem | Check |
| --- | --- |
| Job absent | The jobs run only in branch pipelines; check existing `workflow` rules too |
| Job pending | Check runner availability and any required runner tags |
| Missing token variable | If the variable is protected, protect the branch too, and use environment scope `*` |
| HTTP 401/403 | Verify the backend CI token; do not use a GitLab token as `SAST_API_TOKEN` |
| `scanning is disabled for the project` | A project made in the app has that type off; enable it or drop it from the job |
| HTTP 404 | Check the backend URL |
| Connection refused/timeout | Check runner-to-backend routing, firewall, and TLS trust |
| Repository checkout failed | Private repo: check the job token permissions above, and that the backend can reach your GitLab host |
| Model/preflight error | Verify the model settings and credentials on the Secure Build server |
| Scan stays `queued` | Another scan of the same repository is running; it starts when that one ends |

Cancelling or timing out the GitLab job does not cancel the backend scan; stop it from Secure Build if needed.
