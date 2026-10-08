#!/usr/bin/env python3
"""
OWASP Top 10 Vulnerability Scanner - AWS Bedrock BATCH INFERENCE (Claude
Haiku 4.5), for enterprise-scale (1000s of files) scans where you don't
need results back immediately and want the 50% batch pricing discount.

This is a different execution model from owasp_bedrock_scanner_batched.py
(which is synchronous - concurrent invoke_model calls, live console
progress, results in minutes). This version:

  1. RECONNAISSANCE + TRIAGE + SECRET SCAN
     Identical logic to owasp_bedrock_scanner_batched.py - clone/inventory,
     score files by relevance (Spring/JAX-RS/Servlet/JBoss/JSP all
     covered), free regex secret scan. See that script's comments for
     the reasoning; not re-derived here.

  2. GROUP INTO SMALL RECORDS (not big batches)
     Bedrock's batch API wants MANY records (there's a per-job minimum,
     historically ~100 for Anthropic models - verify your account's
     actual quota), not few large ones. So instead of packing up to 10
     files into one call like the synchronous script, this groups files
     FILES_PER_RECORD (default 3) at a time - smaller prompts, lower
     truncation risk per record, and comfortably clears the minimum
     record count for anything at real enterprise scale.

  3. SUBMIT ONE BATCH JOB (async)
     Write every record to a .jsonl file, upload to S3, call
     create_model_invocation_job(), then poll until the job reaches a
     terminal status. This is a "submit and check back later" workflow -
     minutes to hours, no SLA.

  4. RECOVER TRUNCATED RECORDS SYNCHRONOUSLY
     A batch job doesn't support the live auto-split-and-retry the
     synchronous script does - you only find out a record was truncated
     (stop_reason == "max_tokens") after the whole job finishes. Rather
     than submit a whole second batch job (which has its own minimum-
     record-count problem for what's usually a handful of stragglers),
     truncated record-groups are retried with a single ordinary
     invoke_model call each (bedrock-runtime, standard pricing, higher
     max_tokens) - the same recovery outcome, without needing another
     100+ record batch.

  5. SYNTHESIS (reduce)
     Same as the synchronous script: one ordinary invoke_model call
     (NOT part of the batch job - a single call doesn't benefit from
     batch pricing and batch's per-job minimum makes it a poor fit)
     consolidates all findings into the final ranked report.

  6. COST REPORT
     Batch-phase tokens/cost come straight from Bedrock's manifest.json.out
     summary file (no manual summing). Retry and synthesis costs are
     tracked separately since they're billed at STANDARD (non-batch) rates.
     All three phases + grand total are printed.

ASSUMPTIONS (verify before relying on these for budgeting or in production):
  - Model: Claude Haiku 4.5, base model ID
    'anthropic.claude-haiku-4-5-20251001-v1:0'. Batch inference REJECTS
    cross-region inference profile IDs (the "us.anthropic...." form) -
    must be the base ID.
  - Pricing (Aug 2026, us-east-1, verify at
    https://aws.amazon.com/bedrock/pricing/):
      Batch:    $0.50 / 1M input tokens,  $2.50 / 1M output tokens
      Standard: $1.00 / 1M input tokens,  $5.00 / 1M output tokens
    Retries and synthesis use Standard pricing (they're ordinary
    invoke_model calls, not part of the batch job).
  - EXPECTED_MIN_BATCH_RECORDS (default 100) is a local sanity check
    reflecting what's historically been the Bedrock minimum for
    Anthropic models on batch - it is NOT authoritative. Check
    "Minimum number of records per batch inference job" for your
    account/region/model under Bedrock in the AWS Service Quotas
    console before relying on a number here.
  - You need an S3 bucket and an IAM role that trusts bedrock.amazonaws.com
    with read access to the input prefix and write access to the output
    prefix, BEFORE running this. See the IAM setup notes at the bottom
    of this file - this script does not create the role or bucket for you.
  - job management (create/get/list/stop) uses boto3.client("bedrock") -
    the CONTROL-PLANE client. invoke_model calls (retries + synthesis)
    use boto3.client("bedrock-runtime"). These are different clients;
    mixing them up is the most common first mistake with this API.

Requirements:
    pip install boto3

Usage:
    python owasp_bedrock_scanner_batch_job.py
"""

import json
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import boto3

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

REPO_URL = "https://github.com/mahenderkodi/tdra-ssir-portal.git"
# For a local enterprise checkout instead of cloning:
#   REPO_URL = None
#   LOCAL_REPO_PATH = "/path/to/your/repo"
LOCAL_REPO_PATH = None

AWS_REGION = "us-east-1"
MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"  # base ID - batch rejects inference-profile IDs

# --- S3 + IAM (created via AWS CLI for account 258397330626) ---
S3_BUCKET = "secure-build-bedrock-batch-258397330626"
S3_INPUT_KEY = "bedrock-batch/owasp-scan/input.jsonl"
S3_OUTPUT_PREFIX = "bedrock-batch/owasp-scan/output/"
ROLE_ARN = "arn:aws:iam::258397330626:role/BedrockBatchInferenceRole"

OUTPUT_REPORT_PATH = "OWASP_Vulnerability_Report_Bedrock_Batch.md"

# --- Batch pricing (50% off standard) ---
BATCH_PRICE_PER_INPUT_TOKEN = 0.50 / 1_000_000
BATCH_PRICE_PER_OUTPUT_TOKEN = 2.50 / 1_000_000
# --- Standard pricing (retries + synthesis - NOT part of the batch job) ---
STANDARD_PRICE_PER_INPUT_TOKEN = 1.00 / 1_000_000
STANDARD_PRICE_PER_OUTPUT_TOKEN = 5.00 / 1_000_000

RELEVANT_EXTENSIONS = {
    ".java", ".ts", ".js", ".py", ".go", ".rb", ".php",
    ".xml", ".properties", ".yml", ".yaml", ".json", ".conf", ".env",
    ".jsp", ".jspx", ".tag", ".html", ".htm",
}
RELEVANT_FILENAMES = {"dockerfile", "makefile", "docker-compose.yml", "docker-compose.yaml"}
SKIP_DIRS = {
    ".git", "node_modules", "target", "dist", "build", ".angular",
    "vendor", "venv", ".venv", "__pycache__", "coverage", "wrapper",
}
SKIP_NAME_PATTERNS = (
    ".spec.ts", ".test.ts", ".test.js", "Tests.java", "Test.java",
    ".min.js", ".d.ts", "-lock.json", ".lock",
)
MAX_FILE_SIZE_BYTES = 300_000

# Files per JSONL record. Small on purpose - see module docstring point 2.
FILES_PER_RECORD = 3
CHARS_PER_TOKEN_ESTIMATE = 3.7  # sizing heuristic only, not a billing figure
MAX_TOKENS_PER_RECORD = 2500     # generous for a 3-file group; keeps truncation rare
MAX_TOKENS_RETRY = 6000          # single-record synchronous retry gets more headroom
MAX_TOKENS_SYNTHESIS = 8000

MIN_RELEVANCE_SCORE = 2
EXPECTED_MIN_BATCH_RECORDS = 100  # local sanity check only - see ASSUMPTIONS above
MAX_SYNTHESIS_FINDINGS = 400
POLL_SECONDS = 60
MAX_POLLS = 500  # 500 * 60s ~= 8.3 hours ceiling on this script's own wait loop


# --------------------------------------------------------------------------
# Phase 1: Reconnaissance + triage + secret scan
# (identical approach to owasp_bedrock_scanner_batched.py)
# --------------------------------------------------------------------------

def clone_repo(repo_url: str, dest: Path) -> None:
    print(f"[1/8] Cloning {repo_url} ...")
    subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(dest)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    print(f"      done -> {dest}")


def collect_candidate_files(repo_dir: Path) -> list[Path]:
    files = []
    skipped_large = 0
    for path in repo_dir.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if any(pattern in path.name for pattern in SKIP_NAME_PATTERNS):
            continue
        is_relevant = path.suffix in RELEVANT_EXTENSIONS or path.name.lower() in RELEVANT_FILENAMES
        if not is_relevant:
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                skipped_large += 1
                continue
        except OSError:
            continue
        files.append(path)
    if skipped_large:
        print(f"      skipped {skipped_large} file(s) over {MAX_FILE_SIZE_BYTES:,} bytes "
              f"(likely generated/vendored)")
    return sorted(files)


PATH_SCORE_RULES = [
    (r"controller|endpoint|route|resource|servlet", 3),
    (r"auth|security|login|session|jwt|oauth|token|credential", 3),
    (r"config|properties|application\.(yml|yaml|properties)|web\.xml|jboss.*\.xml|dockerfile", 3),
    (r"service|repository|dao|database|\bdb\b|sql", 2),
    (r"middleware|filter|interceptor|guard|corsfilter", 2),
]

CONTENT_SCORE_RULES = [
    (r"@(RestController|Controller|RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|CrossOrigin)", 3),
    (r"@(Path|GET|POST|PUT|DELETE|Produces|Consumes|ApplicationPath|Provider)\b", 3),
    (r"@(WebServlet|WebFilter)\b|extends\s+HttpServlet|implements\s+Filter\b", 3),
    (r"@(RolesAllowed|PermitAll|DenyAll|DeclareRoles)\b", 3),
    (r"<security-constraint>|<auth-constraint>|<login-config>", 3),
    (r"<%[@=!]?[^-]|request\.getParameter\(", 2),
    (r"password|secret|apikey|api_key|private[_-]?key", 2),
    (r"\b(SELECT|INSERT INTO|UPDATE|DELETE FROM)\b", 2),
    (r"http://", 1),
    (r"eval\(|exec\(|innerHTML|dangerouslySetInnerHTML|subprocess|os\.system", 2),
]

SECRET_PATTERN_RULES = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private key block"),
    (r"://[^/\s:'\"]+:[^/\s@'\"]+@", "credentials embedded in a connection string/URL"),
    (r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b", "GitHub token"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack token"),
    (r"\bsk_live_[A-Za-z0-9]{20,}\b", "Stripe live secret key"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "hardcoded JWT-looking token"),
    (r"(?i)(secret|password|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9+/_=-]{12,}['\"]?",
     "hardcoded value assigned to a secret-looking key"),
]
SECRET_SCORE_BONUS = 6


def score_file(path: Path, repo_dir: Path) -> tuple[int, str, list[str]]:
    rel = str(path.relative_to(repo_dir)).lower()
    score = 0
    for pattern, points in PATH_SCORE_RULES:
        if re.search(pattern, rel):
            score += points
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        text = ""
    for pattern, points in CONTENT_SCORE_RULES:
        if re.search(pattern, text, re.IGNORECASE):
            score += points
    secret_hits = []
    for pattern, label in SECRET_PATTERN_RULES:
        if re.search(pattern, text):
            secret_hits.append(label)
            score += SECRET_SCORE_BONUS
    return score, text, secret_hits


@dataclass
class ScoredFile:
    path: Path
    rel_path: str
    score: int
    text: str
    tokens_estimate: int
    secret_hits: list[str]


def triage_files(repo_dir: Path, files: list[Path]) -> list[ScoredFile]:
    scored = []
    for f in files:
        score, text, secret_hits = score_file(f, repo_dir)
        if score < MIN_RELEVANCE_SCORE:
            continue
        scored.append(ScoredFile(
            path=f, rel_path=str(f.relative_to(repo_dir)), score=score, text=text,
            tokens_estimate=max(1, int(len(text) / CHARS_PER_TOKEN_ESTIMATE)),
            secret_hits=secret_hits,
        ))
    scored.sort(key=lambda sf: (str(sf.path.parent), -sf.score))
    return scored


def print_secret_scan_summary(scored_files: list[ScoredFile]) -> None:
    hits = [sf for sf in scored_files if sf.secret_hits]
    if not hits:
        return
    print(f"      FAST SECRET SCAN (free, regex-based, unverified - {len(hits)} file(s) flagged):")
    for sf in hits:
        print(f"        - {sf.rel_path}: {', '.join(sorted(set(sf.secret_hits)))}")
    print("        (pattern matches, not confirmed findings - verify manually)")


def render_secret_scan_section(scored_files: list[ScoredFile]) -> str:
    hits = [sf for sf in scored_files if sf.secret_hits]
    if not hits:
        return ""
    lines = [
        "## Fast Secret Scan (static pattern match, not LLM-verified)", "",
        "These files matched a hardcoded-secret pattern during triage. Treat as "
        "leads to verify by hand, not confirmed findings.", "",
        "| File | Pattern(s) matched |", "|---|---|",
    ]
    for sf in hits:
        lines.append(f"| {sf.rel_path} | {', '.join(sorted(set(sf.secret_hits)))} |")
    lines.append("\n---\n")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Phase 2: group triaged files into small JSONL records
# --------------------------------------------------------------------------

@dataclass
class Record:
    record_id: str
    files: list[ScoredFile]


def make_records(scored_files: list[ScoredFile]) -> list[Record]:
    records = []
    for i in range(0, len(scored_files), FILES_PER_RECORD):
        group = scored_files[i:i + FILES_PER_RECORD]
        records.append(Record(record_id=f"grp{i // FILES_PER_RECORD:06d}", files=group))
    return records


def render_group_bundle(files: list[ScoredFile]) -> str:
    return "\n".join(f"### FILE: {sf.rel_path}\n```\n{sf.text}\n```\n" for sf in files)


# --------------------------------------------------------------------------
# Prompts (same framework coverage as owasp_bedrock_scanner_batched.py)
# --------------------------------------------------------------------------

BATCH_SYSTEM_PROMPT = """You are an application security engineer \
performing an OWASP Top 10 (2021) static code review on a SMALL GROUP of \
files from a larger codebase.

The codebase may be Spring, JAX-RS/RESTEasy, raw Servlet/JEE, or a mix -
apply whichever actually appears in the code in front of you:
  - Authentication & Authorization: Spring's @PreAuthorize/@Secured, OR \
JAX-RS/JEE's @RolesAllowed/@PermitAll/@DenyAll, OR web.xml \
<security-constraint>/<auth-constraint>/<login-config>
  - Input Validation: @Valid, manual validation, or JSP scriptlets/EL \
using request.getParameter(...) without escaping
  - Configuration: hardcoded values, default credentials, debug flags, \
web.xml/jboss-web.xml settings
  - Dependencies: missing security filters/starters, outdated libraries
  - Frontend Security: HTTPS usage, CSRF/XSRF, XSS (Angular/JS templates \
AND JSP pages)
  - Logging & Monitoring: security event logging, generic exception handling
  - API Security: rate limiting, ID enumeration, CORS filter configuration

Map every finding to an OWASP Top 10 2021 category (A01-A10) and assign a \
CVSS v3.1 base score + severity (CRITICAL/HIGH/MEDIUM/LOW).

Respond with ONLY a JSON array (no prose, no markdown fences) where each \
element has EXACTLY these fields:
  "category", "severity", "cvss", "file", "issue", "location", "risk", \
"recommendation", "example_fix"

If this group has no genuine findings, respond with exactly: []
Do not invent files, line numbers, or issues that aren't present in the \
supplied code."""

SYNTHESIS_SYSTEM_PROMPT = """You are an application security engineer \
producing a final OWASP Top 10 (2021) report for an enterprise codebase, \
from raw findings already collected across many small file-group reviews.

You will receive a JSON array of raw findings. Findings from different \
files very often represent the SAME underlying issue (e.g. "no auth check" \
showing up in 40 endpoints). CONSOLIDATE these into ONE entry per distinct \
root-cause pattern, and list affected file locations under that entry (if \
many, show a representative few and a count) - do not list the same \
pattern dozens of separate times.

From the consolidated list, select and rank the TOP 10 by severity (CVSS \
descending), covering the broadest set of OWASP categories represented.

Respond with ONLY a single markdown report, using EXACTLY this structure:

# OWASP Top 10 Vulnerability Report
## <project/system name, inferred if possible, else "Codebase Review">

**Repository:** <repo>
**Scan Date:** <today's date>
**Severity:** <overall verdict>

---

## Top 10 OWASP Vulnerabilities Found

### N. [emoji] A0X:2021 - <Category> (<SEVERITY>)
**Severity:** <SEVERITY> | **CVSS Score:** <score> | **Affected files:** <count>

**Issue:** <one-line description>

**Location(s):**
```
<representative file(s) + code>
```

**Risk:** <what an attacker can do>

**Recommendation:**
- <fix step>

**Example Fix:**
```
<corrected code>
```
---

## Summary Table
| # | OWASP Category | Severity | CVSS | Affected Files |
|---|---|---|---|---|
| ... |

## Critical Actions Required
### Immediate (Before Production)
- ...
### Short-term
- ...
### Ongoing
- ...

---

**Report Generated:** <date>
**Status:** <verdict>
**Recommendation:** <one-line deployment recommendation>"""


# --------------------------------------------------------------------------
# Phase 3: build JSONL, upload, submit the batch job, poll
# --------------------------------------------------------------------------

def build_batch_jsonl(records: list[Record], local_path: str) -> None:
    with open(local_path, "w", encoding="utf-8") as f:
        for rec in records:
            body = {
                "recordId": rec.record_id,
                "modelInput": {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": MAX_TOKENS_PER_RECORD,
                    "system": BATCH_SYSTEM_PROMPT,
                    "messages": [{
                        "role": "user",
                        "content": f"{len(rec.files)} file(s) in this group.\n\n{render_group_bundle(rec.files)}",
                    }],
                },
            }
            f.write(json.dumps(body) + "\n")


def upload_input(local_path: str) -> str:
    boto3.client("s3", region_name=AWS_REGION).upload_file(local_path, S3_BUCKET, S3_INPUT_KEY)
    return f"s3://{S3_BUCKET}/{S3_INPUT_KEY}"


def create_batch_job(s3_input_uri: str, s3_output_uri: str, job_name: str) -> str:
    bedrock = boto3.client("bedrock", region_name=AWS_REGION)  # control-plane client
    response = bedrock.create_model_invocation_job(
        jobName=job_name,
        roleArn=ROLE_ARN,
        modelId=MODEL_ID,
        inputDataConfig={"s3InputDataConfig": {"s3Uri": s3_input_uri}},
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": s3_output_uri}},
    )
    return response["jobArn"]


TERMINAL_STATUSES = {"Completed", "Failed", "Stopped", "PartiallyCompleted", "Expired"}


def poll_batch_job(job_arn: str) -> str:
    bedrock = boto3.client("bedrock", region_name=AWS_REGION)
    for _ in range(MAX_POLLS):
        info = bedrock.get_model_invocation_job(jobIdentifier=job_arn)
        status = info["status"]
        print(f"      job status: {status}")
        if status in TERMINAL_STATUSES:
            if status != "Completed":
                print(f"      message: {info.get('message', '(none)')}")
            return status
        time.sleep(POLL_SECONDS)
    raise TimeoutError(f"batch job did not finish after {MAX_POLLS} polls")


# --------------------------------------------------------------------------
# Phase 4: parse batch results; synchronously retry any truncated records
# --------------------------------------------------------------------------

def job_output_prefix(job_arn: str) -> str:
    job_id = job_arn.rstrip("/").split("/")[-1]
    return f"{S3_OUTPUT_PREFIX.rstrip('/')}/{job_id}/"


def parse_json_findings(text: str) -> list[dict] | None:
    """Returns None (not []) on parse failure, so callers can tell
    'genuinely no findings' apart from 'couldn't parse'."""
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```(json)?", "", candidate).strip()
        candidate = re.sub(r"```$", "", candidate).strip()
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        match = re.search(r"\[.*\]", candidate, re.DOTALL)
        if not match:
            return None
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, list) else None


def parse_batch_results(job_arn: str) -> tuple[dict[str, list[dict]], list[str], dict]:
    """Returns (findings_by_record_id, truncated_or_failed_record_ids, manifest)."""
    s3 = boto3.client("s3", region_name=AWS_REGION)
    prefix = job_output_prefix(job_arn)
    findings_by_id: dict[str, list[dict]] = {}
    needs_retry: list[str] = []
    manifest: dict = {}

    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            body = s3.get_object(Bucket=S3_BUCKET, Key=key)["Body"].read().decode("utf-8")

            if key.endswith("manifest.json.out"):
                manifest = json.loads(body)
                continue
            if not key.endswith(".jsonl.out"):
                continue

            for line in body.strip().splitlines():
                if not line:
                    continue
                record = json.loads(line)
                record_id = record["recordId"]

                if "error" in record:
                    print(f"      WARNING: {record_id} errored: {record['error']}")
                    needs_retry.append(record_id)
                    continue

                model_output = record["modelOutput"]
                truncated = model_output.get("stop_reason") == "max_tokens"
                text = "".join(b.get("text", "") for b in model_output.get("content", [])
                               if b.get("type") == "text")
                parsed = parse_json_findings(text)

                if parsed is None or truncated:
                    reason = "truncated" if truncated else "unparseable JSON"
                    print(f"      {record_id}: {reason} in batch output - queued for sync retry")
                    needs_retry.append(record_id)
                    continue

                findings_by_id[record_id] = parsed

    return findings_by_id, needs_retry, manifest


def retry_records_synchronously(records_by_id: dict[str, Record], retry_ids: list[str]) -> tuple[list[dict], dict]:
    """Retries a (usually small) set of records that came back truncated or
    errored from the batch job, using ordinary invoke_model calls with more
    headroom (MAX_TOKENS_RETRY). Billed at STANDARD rates, not batch."""
    if not retry_ids:
        return [], {"input_tokens": 0, "output_tokens": 0}

    print(f"[6/8] Synchronously retrying {len(retry_ids)} record(s) that failed in the batch job ...")
    client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
    all_findings: list[dict] = []
    usage_totals = {"input_tokens": 0, "output_tokens": 0}

    for record_id in retry_ids:
        rec = records_by_id[record_id]
        user_message = f"{len(rec.files)} file(s) in this group.\n\n{render_group_bundle(rec.files)}"
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": MAX_TOKENS_RETRY,
            "system": BATCH_SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_message}],
        }
        response = client.invoke_model(
            modelId=MODEL_ID, body=json.dumps(body),
            contentType="application/json", accept="application/json",
        )
        payload = json.loads(response["body"].read())
        usage = payload.get("usage", {})
        usage_totals["input_tokens"] += usage.get("input_tokens", 0)
        usage_totals["output_tokens"] += usage.get("output_tokens", 0)

        text = "".join(b.get("text", "") for b in payload.get("content", []) if b.get("type") == "text")
        parsed = parse_json_findings(text)
        if parsed is None:
            print(f"      WARNING: {record_id} still unparseable after sync retry - giving up on it")
            continue
        all_findings.extend(parsed)

    return all_findings, usage_totals


# --------------------------------------------------------------------------
# Phase 5: synthesis (single ordinary invoke_model call)
# --------------------------------------------------------------------------

def _cvss_key(finding: dict) -> float:
    try:
        return float(finding.get("cvss", 0))
    except (TypeError, ValueError):
        return 0.0


def run_synthesis(all_findings: list[dict]) -> tuple[str, dict]:
    if len(all_findings) > MAX_SYNTHESIS_FINDINGS:
        print(f"      {len(all_findings)} raw findings exceeds synthesis cap of "
              f"{MAX_SYNTHESIS_FINDINGS} - keeping the highest-CVSS subset")
        all_findings = sorted(all_findings, key=_cvss_key, reverse=True)[:MAX_SYNTHESIS_FINDINGS]

    print(f"[7/8] Synthesizing {len(all_findings)} raw findings into final report ...")
    client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": MAX_TOKENS_SYNTHESIS,
        "system": SYNTHESIS_SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": f"Raw findings collected from all groups:\n\n{json.dumps(all_findings)}"}],
    }
    response = client.invoke_model(
        modelId=MODEL_ID, body=json.dumps(body),
        contentType="application/json", accept="application/json",
    )
    payload = json.loads(response["body"].read())
    text = "".join(b.get("text", "") for b in payload.get("content", []) if b.get("type") == "text")
    return text, payload.get("usage", {})


# --------------------------------------------------------------------------
# Cost reporting - three phases at two different rates
# --------------------------------------------------------------------------

def print_cost_report(manifest: dict, retry_usage: dict, synthesis_usage: dict,
                       num_candidates: int, num_triaged: int, num_records: int) -> None:
    batch_in = manifest.get("inputTokenCount", 0)
    batch_out = manifest.get("outputTokenCount", 0)
    batch_cost = batch_in * BATCH_PRICE_PER_INPUT_TOKEN + batch_out * BATCH_PRICE_PER_OUTPUT_TOKEN

    retry_in = retry_usage.get("input_tokens", 0)
    retry_out = retry_usage.get("output_tokens", 0)
    retry_cost = retry_in * STANDARD_PRICE_PER_INPUT_TOKEN + retry_out * STANDARD_PRICE_PER_OUTPUT_TOKEN

    synth_in = synthesis_usage.get("input_tokens", 0)
    synth_out = synthesis_usage.get("output_tokens", 0)
    synth_cost = synth_in * STANDARD_PRICE_PER_INPUT_TOKEN + synth_out * STANDARD_PRICE_PER_OUTPUT_TOKEN

    grand_total_tokens = batch_in + batch_out + retry_in + retry_out + synth_in + synth_out
    grand_total_cost = batch_cost + retry_cost + synth_cost

    print("\n" + "=" * 68)
    print("  TOKEN USAGE & COST  (Claude Haiku 4.5 / AWS Bedrock BATCH job)")
    print("=" * 68)
    print(f"  Files discovered:        {num_candidates:>8,}")
    print(f"  Files sent to LLM:       {num_triaged:>8,}  (after relevance triage)")
    print(f"  Batch records:           {num_records:>8,}  ({FILES_PER_RECORD} files/record)")
    print(f"  Hard errors (manifest):  {manifest.get('errorRecordCount', 0):>8,}  "
          f"(truncated-but-valid records are retried too - see the run log above)")
    print("-" * 68)
    print(f"  BATCH   input:  {batch_in:>10,} tok  @ $0.50/1M")
    print(f"  BATCH   output: {batch_out:>10,} tok  @ $2.50/1M")
    print(f"  BATCH   subtotal:                     ${batch_cost:.4f}")
    print("-" * 68)
    print(f"  RETRY   input:  {retry_in:>10,} tok  @ $1.00/1M (standard rate)")
    print(f"  RETRY   output: {retry_out:>10,} tok  @ $5.00/1M (standard rate)")
    print(f"  RETRY   subtotal:                     ${retry_cost:.4f}")
    print("-" * 68)
    print(f"  SYNTHESIS input:  {synth_in:>8,} tok  @ $1.00/1M (standard rate)")
    print(f"  SYNTHESIS output: {synth_out:>8,} tok  @ $5.00/1M (standard rate)")
    print(f"  SYNTHESIS subtotal:                   ${synth_cost:.4f}")
    print("=" * 68)
    print(f"  TOTAL TOKENS:            {grand_total_tokens:>8,}")
    print(f"  TOTAL COST:              ${grand_total_cost:.4f}")
    print("=" * 68)
    print("  Batch rate is 50% off standard - verify current rates at")
    print("  https://aws.amazon.com/bedrock/pricing/")
    print("=" * 68 + "\n")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> None:
    tmpdir = Path(tempfile.mkdtemp(prefix="owasp-batch-scan-"))
    try:
        if LOCAL_REPO_PATH:
            repo_dir = Path(LOCAL_REPO_PATH)
            repo_label = str(repo_dir)
            print(f"[1/8] Using local checkout -> {repo_dir}")
        else:
            repo_dir = tmpdir / "repo"
            clone_repo(REPO_URL, repo_dir)
            repo_label = REPO_URL

        print("[2/8] Inventorying + triaging files ...")
        candidates = collect_candidate_files(repo_dir)
        scored = triage_files(repo_dir, candidates)
        print(f"      {len(candidates)} candidate files -> {len(scored)} pass relevance "
              f"triage (min score {MIN_RELEVANCE_SCORE})")
        print_secret_scan_summary(scored)

        if not scored:
            print("      No files passed triage - nothing to scan.")
            return

        records = make_records(scored)
        records_by_id = {r.record_id: r for r in records}
        print(f"      grouped into {len(records)} record(s) ({FILES_PER_RECORD} files/record)")
        if len(records) < EXPECTED_MIN_BATCH_RECORDS:
            print(f"      WARNING: {len(records)} records is under the expected batch minimum "
                  f"of ~{EXPECTED_MIN_BATCH_RECORDS} - the job may fail Bedrock's validation. "
                  f"Lower FILES_PER_RECORD, lower MIN_RELEVANCE_SCORE, or use "
                  f"owasp_bedrock_scanner_batched.py (synchronous) instead for a repo this size.")

        local_jsonl = str(tmpdir / "batch-input.jsonl")
        build_batch_jsonl(records, local_jsonl)

        print(f"[3/8] Uploading {len(records)} records to s3://{S3_BUCKET}/{S3_INPUT_KEY} ...")
        s3_input_uri = upload_input(local_jsonl)
        s3_output_uri = f"s3://{S3_BUCKET}/{S3_OUTPUT_PREFIX}"

        job_name = f"owasp-scan-{int(time.time())}"
        print(f"[4/8] Creating batch job '{job_name}' ...")
        job_arn = create_batch_job(s3_input_uri, s3_output_uri, job_name)
        print(f"      jobArn: {job_arn}")

        print("[5/8] Polling for completion (this can take minutes to hours) ...")
        status = poll_batch_job(job_arn)
        if status not in ("Completed", "PartiallyCompleted"):
            print(f"      Job ended with status {status} - stopping.")
            return

        findings_by_id, needs_retry, manifest = parse_batch_results(job_arn)
        all_findings = [f for group in findings_by_id.values() for f in group]
        print(f"      {len(all_findings)} findings from {len(findings_by_id)} successful records; "
              f"{len(needs_retry)} record(s) need a sync retry")

        retry_findings, retry_usage = retry_records_synchronously(records_by_id, needs_retry)
        all_findings.extend(retry_findings)

        report_text, synthesis_usage = run_synthesis(all_findings) if all_findings else (
            f"# OWASP Top 10 Vulnerability Report\n\n**Repository:** {repo_label}\n"
            f"**Scan Date:** {datetime.now(timezone.utc).date()}\n\n"
            f"No vulnerabilities were flagged across {len(scored)} triaged files.\n",
            {"input_tokens": 0, "output_tokens": 0},
        )
        report_text = render_secret_scan_section(scored) + report_text

        print(f"[8/8] Writing report -> {OUTPUT_REPORT_PATH}")
        Path(OUTPUT_REPORT_PATH).write_text(report_text, encoding="utf-8")

        print_cost_report(manifest, retry_usage, synthesis_usage,
                           len(candidates), len(scored), len(records))

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()


# --------------------------------------------------------------------------
# ONE-TIME AWS SETUP (do this before running the script)
# --------------------------------------------------------------------------
#
# 1. Create an S3 bucket (or reuse one) in the same region as AWS_REGION.
#
# 2. Create an IAM role Bedrock can assume, with this trust policy:
#
#    {
#      "Version": "2012-10-17",
#      "Statement": [{
#        "Effect": "Allow",
#        "Principal": {"Service": "bedrock.amazonaws.com"},
#        "Action": "sts:AssumeRole"
#      }]
#    }
#
# 3. Attach a permissions policy to that role (replace your-bucket-name):
#
#    {
#      "Version": "2012-10-17",
#      "Statement": [
#        {
#          "Effect": "Allow",
#          "Action": ["s3:GetObject", "s3:ListBucket"],
#          "Resource": [
#            "arn:aws:s3:::your-bucket-name",
#            "arn:aws:s3:::your-bucket-name/bedrock-batch/owasp-scan/input.jsonl"
#          ]
#        },
#        {
#          "Effect": "Allow",
#          "Action": ["s3:PutObject"],
#          "Resource": "arn:aws:s3:::your-bucket-name/bedrock-batch/owasp-scan/output/*"
#        }
#      ]
#    }
#
# 4. Put that role's ARN into ROLE_ARN above, and your bucket name into
#    S3_BUCKET above.
#
# (AWS also offers a "create a default service role" option in the Bedrock
# console when you create a batch job there, which does 1-3 for you.)