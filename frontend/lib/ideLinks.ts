/**
 * Deep link that hands a finding straight to a locally installed Claude
 * Code CLI session.
 *
 * `claude-cli://` is resolved entirely by the OS on whichever machine clicks
 * the link — there is no server round-trip. That only works here because
 * `localRootPath` (see `Scan.local_root_path`) is the backend's own
 * checkout path, so this link is only meaningful when the browser is opened
 * on the same machine as the backend.
 */

import type { Finding } from "@/lib/types";

/** Claude Code's documented `q` parameter cap; leave headroom for the rest
 *  of the prompt scaffolding added around the snippet/ai_fix text. */
const CLAUDE_PROMPT_MAX_CHARS = 4500;

/**
 * `claude-cli://open?cwd=...&q=...` — opens a new terminal in `cwd` with the
 * prompt pre-filled (never auto-sent; the user still presses Enter). `cwd` is
 * kept in its native form (backslashes on Windows) since it travels as a
 * fully percent-encoded query value, not a URI path segment.
 */
export function buildClaudeCodeLink(rootPath: string, prompt: string): string {
  const params = new URLSearchParams();
  if (rootPath) params.set("cwd", rootPath);
  params.set("q", prompt);
  return `claude-cli://open?${params.toString()}`;
}

/** Assembles the "what to fix" prompt from data the scan already computed —
 *  no extra LLM call needed. Truncates the snippet first (the bulkiest,
 *  least essential part once ai_fix/verdict_reason are present) to stay
 *  under Claude Code's 5,000-char `q` limit. */
export function buildFixPrompt(finding: Finding): string {
  const lines: string[] = [];
  const location = finding.file_path
    ? `${finding.file_path}${finding.line ? `:${finding.line}` : ""}`
    : "unknown file";
  lines.push(`Fix this security finding in ${location}.`);
  lines.push(`Title: ${finding.title}`);
  if (finding.severity) lines.push(`Severity: ${finding.severity}`);
  if (finding.cwe) lines.push(`CWE: ${finding.cwe}`);
  if (finding.owasp_category) lines.push(`OWASP category: ${finding.owasp_category}`);
  if (finding.verdict_reason) lines.push(`Why it's a problem: ${finding.verdict_reason}`);
  if (finding.affected_files && finding.affected_files.length > 1) {
    lines.push(
      `This same pattern also appears in ${finding.affected_files.length - 1} other file(s): ${finding.affected_files
        .filter((p) => p !== finding.file_path)
        .slice(0, 10)
        .join(", ")}${finding.affected_files.length > 11 ? ", ..." : ""}`,
    );
  }
  if (finding.ai_fix) {
    lines.push("");
    lines.push(`Suggested remediation: ${finding.ai_fix}`);
  }
  if (finding.snippet) {
    lines.push("");
    lines.push("Relevant code:");
    lines.push(finding.snippet);
  }

  let prompt = lines.join("\n");
  if (prompt.length > CLAUDE_PROMPT_MAX_CHARS) {
    const withoutSnippet = lines
      .slice(0, lines.indexOf("Relevant code:") > -1 ? lines.indexOf("Relevant code:") : lines.length)
      .join("\n");
    prompt =
      withoutSnippet.length <= CLAUDE_PROMPT_MAX_CHARS
        ? withoutSnippet
        : withoutSnippet.slice(0, CLAUDE_PROMPT_MAX_CHARS);
  }
  return prompt;
}
