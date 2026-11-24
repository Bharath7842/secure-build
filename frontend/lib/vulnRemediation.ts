import type { Finding, VulnReportItem } from "@/lib/types";
import { SCAN_TYPE_LABEL, SEVERITY_LABEL } from "@/lib/vulnReport";

/** Standard fix guidance per CWE, used when the scanner stored no fix of its own. */
const CWE_GUIDANCE: Record<number, string[]> = {
  20: ["Validate every input against an allow-list of type, length, format and range.", "Reject invalid input on the server; never rely on client-side checks."],
  22: ["Resolve the path with a canonical form and check it stays inside an allowed base directory.", "Never build file paths from user input; map user choices to server-side ids instead."],
  77: ["Avoid invoking a shell; call the program directly with an argument array.", "Allow-list any value that must reach a command."],
  78: ["Avoid invoking a shell; call the program directly with an argument array (e.g. ProcessBuilder with separate args).", "Allow-list any user-controlled value that reaches the command."],
  79: ["Encode output for its context (HTML body, attribute, JavaScript, URL) with a framework encoder.", "Do not echo request data or exception messages into responses; use templating that escapes by default.", "Add a Content-Security-Policy as defence in depth."],
  89: ["Use parameterised queries / PreparedStatement with bound parameters; never concatenate input into SQL.", "For dynamic identifiers (column, sort order), map input to an allow-list of fixed values."],
  90: ["Escape LDAP filter values with a library encoder, or use parameterised LDAP APIs."],
  94: ["Never evaluate user-controlled data as code (eval, script engines, expression languages).", "Allow-list the operations a user may choose instead."],
  117: ["Strip or encode CR/LF characters before logging untrusted values, or use a structured (JSON) log layout.", "Prefer parameterised logging with a log layout that neutralises line breaks."],
  200: ["Return generic error messages to clients; log details server-side only.", "Remove stack traces, versions and internal identifiers from responses."],
  209: ["Return a generic error message to the client and log the exception server-side.", "Map exceptions to safe, fixed messages in a central exception handler."],
  250: ["Run the process or container as a non-root user with the minimum privileges it needs."],
  259: ["Remove the hard-coded password; read it from a secret manager or environment at runtime.", "Rotate the exposed credential."],
  295: ["Keep TLS certificate and hostname verification enabled; never trust all certificates."],
  311: ["Encrypt sensitive data at rest and in transit with platform-managed keys."],
  319: ["Use HTTPS/TLS for every connection that carries sensitive data, and redirect HTTP to HTTPS."],
  326: ["Use current key sizes (RSA ≥ 2048, ECC ≥ 256, AES-256)."],
  327: ["Replace broken algorithms (MD5, SHA-1, DES, ECB mode) with modern ones (SHA-256+, AES-GCM)."],
  330: ["Use a cryptographically secure random generator (SecureRandom, crypto.randomBytes, secrets)."],
  345: ["Validate token signature, expiry, issuer (iss) and audience (aud) before trusting it."],
  352: ["Keep CSRF protection enabled for cookie-authenticated, state-changing requests.", "Use SameSite cookies and verify a CSRF token on every state-changing request."],
  377: ["Create temporary files with secure APIs that set restrictive permissions."],
  400: ["Limit request sizes, rates and resource usage per client."],
  434: ["Validate file type by content, limit size, store uploads outside the web root with generated names."],
  489: ["Remove debug code and debug endpoints from production builds."],
  502: ["Do not deserialize untrusted data with native serializers; use a data-only format (JSON) with strict schemas.", "If unavoidable, allow-list the classes that may be deserialized."],
  521: ["Enforce a strong password policy and use a slow password hash (bcrypt, Argon2)."],
  532: ["Do not log secrets, tokens, passwords or personal data; mask them before logging."],
  598: ["Send sensitive data in the request body or headers, never in the URL query string."],
  601: ["Allow-list redirect targets, or redirect only to relative paths you control."],
  611: ["Disable DTDs and external entities in the XML parser (XXE)."],
  614: ["Set the Secure flag on cookies that carry session or sensitive data."],
  639: ["Check on the server that the current user owns or may access the requested object."],
  732: ["Restrict file and resource permissions to the owner that needs them."],
  798: ["Remove hard-coded credentials or keys; load them from a secret manager or environment.", "Rotate the exposed secret and purge it from git history."],
  862: ["Add an authorization check (e.g. @PreAuthorize / route guard) on the server for this operation."],
  863: ["Verify the user's role and permissions on the server before performing the action."],
  915: ["Bind requests to explicit DTOs with only the fields a user may set (no mass assignment)."],
  918: ["Allow-list destination hosts and schemes; block internal and metadata addresses (SSRF)."],
  942: ["Allow-list trusted CORS origins; never reflect the Origin header or use * with credentials."],
  1004: ["Set the HttpOnly flag on session cookies."],
  1104: ["Upgrade unmaintained third-party components or replace them."],
  191: ["Check bounds before subtracting or decrementing values that feed an index, size or loop bound."],
};

function cweNumber(cwe: string | null): number | null {
  const m = /\d+/.exec(cwe ?? "");
  return m ? Number(m[0]) : null;
}

/** Fix steps for one vulnerability, most specific first. */
export function remediationSteps(v: VulnReportItem): { source: "scanner" | "guidance"; steps: string[] } {
  if (v.ai_fix?.trim()) return { source: "scanner", steps: [v.ai_fix.trim()] };

  if (v.scan_type === "sca") {
    return {
      source: "guidance",
      steps: [
        "Upgrade the affected package to a version that fixes this advisory (check the advisory for the first fixed version).",
        v.file_path ? `Update the version in ${v.file_path} (and the lock file), rebuild and run the tests.` : "Update the dependency version and the lock file, rebuild and run the tests.",
        "If no fixed version exists, remove or replace the package, or mitigate the vulnerable code path and accept the risk explicitly.",
      ],
    };
  }
  if (v.scan_type === "sbom") {
    return {
      source: "guidance",
      steps: [
        "Confirm the component's license with its publisher or package registry.",
        "If it is commercial or unclear, get legal approval or a commercial license, or replace it with a permissively licensed alternative.",
        "Once approved, mark the finding as risk accepted so it stops showing as open.",
      ],
    };
  }
  const n = cweNumber(v.cwe);
  const steps = (n != null && CWE_GUIDANCE[n]) || [
    "Read the flagged code and confirm whether untrusted input can reach it.",
    "Apply the standard fix for this weakness class (see the CWE entry), then add a test that proves it.",
  ];
  return { source: "guidance", steps };
}

export function cweUrl(cwe: string | null): string | null {
  const n = cweNumber(cwe);
  return n != null ? `https://cwe.mitre.org/data/definitions/${n}.html` : null;
}

/** A self-contained prompt a developer can paste into an AI coding assistant to fix this issue. */
export function buildFixPrompt(v: VulnReportItem, projectName: string): string {
  const where = v.file_path ? `${v.file_path}${v.line ? `:${v.line}` : ""}` : v.target ?? "unknown location";
  const lines: string[] = [];
  lines.push(`You are a senior application security engineer. Fix this ${SCAN_TYPE_LABEL[v.scan_type]} finding in the "${projectName}" repository.`);
  lines.push("");
  lines.push("## Finding");
  lines.push(`- Title: ${v.title}`);
  lines.push(`- Severity: ${SEVERITY_LABEL[v.severity]}${v.cvss != null ? ` (CVSS ${v.cvss.toFixed(1)}${v.cvss_vector ? `, ${v.cvss_vector}` : ""})` : ""}`);
  if (v.cwe) lines.push(`- Weakness: ${v.cwe}${v.owasp ? ` · ${v.owasp}` : ""}`);
  if (v.rule_id) lines.push(`- Rule: ${v.rule_id}`);
  lines.push(`- Location: ${where}`);
  if (v.param) lines.push(`- Parameter: ${v.param}`);
  if (v.source) lines.push(`- Untrusted source: ${v.source}`);
  if (v.sink) lines.push(`- Dangerous sink: ${v.sink}`);
  if (v.data_flow) lines.push(`- Data flow: ${v.data_flow}`);
  if (v.verdict_reason) lines.push(`- Scanner reasoning: ${v.verdict_reason}`);
  if (v.risk) lines.push(`- Risk: ${v.risk}`);

  if (v.snippet) {
    lines.push("");
    lines.push("## Flagged code");
    lines.push("```");
    lines.push(v.snippet);
    lines.push("```");
  }

  const { steps } = remediationSteps(v);
  lines.push("");
  lines.push("## Suggested remediation");
  for (const step of steps) lines.push(`- ${step}`);
  if (v.example_fix) {
    lines.push("");
    lines.push("Example fix:");
    lines.push("```");
    lines.push(v.example_fix);
    lines.push("```");
  }

  lines.push("");
  lines.push("## What to do");
  if (v.scan_type === "sca") {
    lines.push("1. Find where this dependency is declared (manifest and lock file) and upgrade it to the first fixed version or later.");
    lines.push("2. Fix any breaking API changes the upgrade causes.");
    lines.push("3. Build the project and run the test suite.");
  } else if (v.scan_type === "sbom") {
    lines.push("1. Identify where this component is declared and what uses it.");
    lines.push("2. Propose a permissively licensed alternative, or explain what license approval is needed.");
  } else {
    lines.push(`1. Open ${where} and confirm the issue: can untrusted input reach this code?`);
    lines.push("2. If it is a real issue, apply the smallest change that removes the vulnerability; keep existing behaviour for valid input.");
    lines.push("3. Fix the root cause — do not suppress the warning, add a comment-only change, or disable the check.");
    lines.push("4. Look for the same pattern elsewhere in the codebase and fix those too.");
    lines.push("5. Add or update a unit test that would fail on the vulnerable code and passes on the fix.");
  }
  lines.push("");
  lines.push("Reply with the diff, a short explanation of why it fixes the issue, and how to test it. If you conclude it is a false positive, explain exactly why instead of changing code.");
  return lines.join("\n");
}

const JIRA_PRIORITY: Record<string, string> = {
  CRITICAL: "Highest",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Low",
};

export type JiraTicketFields = {
  summary: string;
  issueType: string;
  priority: string;
  labels: string;
  description: string;
};

/** Split a Netra Jira reply into the fields a developer copies into Jira. */
export function parseJiraTicket(markdown: string): JiraTicketFields {
  const sections: Record<string, string> = {};
  let current = "";
  for (const line of markdown.split(/\r?\n/)) {
    const heading = /^##\s+(.+?)\s*$/.exec(line);
    if (heading) {
      current = heading[1].trim().toLowerCase();
      sections[current] = "";
      continue;
    }
    if (current) sections[current] = (sections[current] ? sections[current] + "\n" : "") + line;
  }
  const grab = (...names: string[]) => {
    for (const name of names) {
      const value = sections[name]?.trim();
      if (value) return value;
    }
    return "";
  };
  return {
    summary: grab("summary"),
    issueType: grab("issue type", "type"),
    priority: grab("priority"),
    labels: grab("labels"),
    description: grab("description") || markdown.trim(),
  };
}

/** A Jira-shaped ticket when Netra is not used (SCA / SBOM / DAST). */
export function jiraTicketMarkdown(v: VulnReportItem): string {
  const where = v.file_path ? `${v.file_path}${v.line ? `:${v.line}` : ""}` : v.target ?? "unknown location";
  const { steps } = remediationSteps(v);
  const labels = ["security", v.scan_type, v.cwe ? v.cwe.toLowerCase().replace("cwe-", "cwe-") : null]
    .filter(Boolean)
    .join(", ");
  const lines: string[] = [
    "## Summary",
    `[${v.severity}] ${v.title}`.slice(0, 120),
    "",
    "## Issue type",
    "Bug",
    "",
    "## Priority",
    JIRA_PRIORITY[v.severity] ?? "Medium",
    "",
    "## Labels",
    labels,
    "",
    "## Description",
    v.risk?.trim() || v.verdict_reason?.trim() || v.title,
    "",
    `*Location:* ${where}`,
  ];
  if (v.short_id) lines.push(`*Issue ID:* ${v.short_id}`);
  if (v.cwe) lines.push(`*CWE:* ${v.cwe}`);
  if (v.snippet) {
    lines.push("", "*Evidence:*", "{code}", v.snippet, "{code}");
  }
  if (v.source || v.sink) {
    lines.push("");
    if (v.source) lines.push(`*Source:* ${v.source}`);
    if (v.sink) lines.push(`*Sink:* ${v.sink}`);
  }
  lines.push("", "*Suggested fix:*");
  for (const step of steps) lines.push(`* ${step}`);
  if (v.short_id) {
    lines.push("", `Paste into Claude Code: \`/secure-fix ${v.short_id} plan\``);
  }
  return lines.join("\n");
}

/** The Finding shape the Netra drawer reads, built from a report row (its newest occurrence). */
export function asNetraFinding(v: VulnReportItem): Finding {
  return {
    id: v.last_finding_id,
    scan_id: v.last_scan_id,
    severity: v.severity,
    cvss: v.cvss,
    cvss_vector: v.cvss_vector,
    cwe: v.cwe,
    owasp_category: v.owasp,
    rule_id: v.rule_id,
    title: v.title,
    file_path: v.file_path,
    line: v.line,
    snippet: v.snippet,
    ai_fix: v.ai_fix,
    kind: v.kind,
    verdict: v.verdict,
    confidence: null,
    source: v.source,
    sink: v.sink,
    data_flow: v.data_flow,
    verdict_reason: v.verdict_reason,
    issue_class: v.issue_class as Finding["issue_class"],
    unresolved_reason: v.unresolved_reason,
    affected_files: null,
    matched_text: v.matched_text,
    flow_path: null,
    short_id: v.short_id,
  };
}
