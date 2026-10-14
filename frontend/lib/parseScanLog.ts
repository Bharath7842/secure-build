import type { ScanLogLine } from "@/lib/types";

/** One continuous section in the agent run — a chat-like message group. */
export interface AgentSection {
  seq: number;
  label: string;
  lines: string[];
}

// The discovery agent (AgentTrace) prints "### <label>" once per step change.
// Anything before the first banner (workspace prep, git checkout, etc.) is
// grouped under an implicit "Preparing scan" section.
const SECTION_RE = /^###\s*(.+)$/;

// The deep-scan and triage banners name the risk tiers each stage holds in
// this scan ("Scanning CRITICAL files (deep scan)", "Scanning
// HIGH/MEDIUM/LOW files (triage)"); the fixed labels are older scans'.
export const DEEP_SCAN_SECTION_RE = /^Scanning .+ files \(deep scan\)$|^Scanning CRITICAL\/HIGH files$/i;
export const TRIAGE_SECTION_RE = /^Scanning .+ files \(triage\)$|^Scanning MEDIUM\/LOW files$/i;

// Older scans logged full LLM response dumps (`LLM response (...):` + `│ …`
// slices). New runs no longer emit these; keep skip helpers so historical
// logs don't flood the live feed.
const LLM_RESPONSE_HEADER_RE = /^LLM response \(.+:\d+-\d+,\s*[\d,]+ chars\):$/;
const LLM_RESPONSE_BOUNDARY_RES = [
  /^LLM chunk \d+\/\d+ for /,
  /^Scanning deep-risk file \d+\/\d+: /,
  /^Regex-scanning triage-risk file \d+\/\d+: /,
  // Removed agentic hunt, kept for historical scan logs.
  /^Hunting hypothesis \d+\/\d+: /,
  // Pre-rename per-file progress lines, kept for historical scan logs.
  /^Scanning CRITICAL file \d+\/\d+: /,
  /^Scanning LLM-risk file \d+\/\d+: /,
  /^Regex-scanning LOW-risk file \d+\/\d+: /,
  /—\s*\d+\s*confirmed,\s*\d+\s*dismissed\s*\(/,
];

/** True if `line` starts a legacy LLM-response dump block. */
export function isLlmResponseHeaderLine(line: string): boolean {
  return LLM_RESPONSE_HEADER_RE.test(line);
}

/** True once a legacy LLM-response dump block has ended. */
export function isLlmResponseBoundaryLine(line: string): boolean {
  return LLM_RESPONSE_BOUNDARY_RES.some((re) => re.test(line)) || isLlmResponseHeaderLine(line);
}

/** ASCII / box-drawing tree lines from the discovery agent's project structure. */
export function isProjectStructureTreeLine(line: string): boolean {
  return (
    line.startsWith("├──") ||
    line.startsWith("└──") ||
    line.startsWith("│") ||
    // Bare path/directory header, e.g. "src/main/java:" — no spaces, so
    // narrative sentences that happen to end in ":" don't false-positive.
    /^[A-Za-z0-9][\w.\-/]*:$/.test(line)
  );
}

/** Pull the project-structure tree out of agent log lines, if present. */
export function extractProjectStructureTree(lines: ScanLogLine[]): string[] | null {
  const texts = lines.map((l) => l.line.trim()).filter(Boolean);
  for (let i = 0; i < texts.length; i++) {
    if (texts[i] !== "Project structure:") continue;
    const tree: string[] = [];
    let j = i + 1;
    while (j < texts.length && isProjectStructureTreeLine(texts[j])) {
      tree.push(texts[j]);
      j += 1;
    }
    if (tree.length > 0) return tree;
  }
  return null;
}

export function parseScanLogLines(lines: ScanLogLine[]): AgentSection[] {
  const sections: AgentSection[] = [];
  let current: AgentSection | null = null;

  const open = (seq: number, label: string) => {
    current = { seq, label, lines: [] };
    sections.push(current);
  };

  for (const { seq, line } of lines) {
    const trimmed = line.trim();
    if (!trimmed || /^=+$/.test(trimmed)) continue;

    const match = trimmed.match(SECTION_RE);
    if (match) {
      open(seq, match[1].trim());
      continue;
    }

    if (!current) {
      open(seq, "Preparing scan");
    }
    current!.lines.push(trimmed);
  }

  return sections;
}
