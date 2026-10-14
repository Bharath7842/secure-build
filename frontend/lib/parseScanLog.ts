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

// Parallel engine stages (flows, deep scan, triage) prefix every line with
// "[[stage:<name>]] " because their output interleaves. Tagged lines go to the
// latest section that stage opened; untagged lines (every log persisted before
// parallel stages, and everything outside the fan-out) stay positional. A few
// untagged lines are written from worker threads mid-fan-out (e.g. "Saved N
// finding(s)"); they join the section of the most recent tagged line.
const STAGE_TAG_RE = /^\[\[stage:([\w-]+)\]\]\s?(.*)$/;
const STAGE_FINISHED_RE = /^Stage finished: /;

export function parseScanLogLines(lines: ScanLogLine[]): AgentSection[] {
  const sections: AgentSection[] = [];
  let current: AgentSection | null = null;
  const stageSection = new Map<string, AgentSection>();
  let lastTagged: AgentSection | null = null;

  const open = (seq: number, label: string): AgentSection => {
    const section = { seq, label, lines: [] as string[] };
    sections.push(section);
    return section;
  };

  for (const { seq, line } of lines) {
    let trimmed = line.trim();
    if (!trimmed || /^=+$/.test(trimmed)) continue;

    const tagged = trimmed.match(STAGE_TAG_RE);
    if (tagged) {
      const stage = tagged[1];
      trimmed = tagged[2].trim();
      if (!trimmed || STAGE_FINISHED_RE.test(trimmed)) continue;
      const banner = trimmed.match(SECTION_RE);
      if (banner) {
        const section = open(seq, banner[1].trim());
        stageSection.set(stage, section);
        lastTagged = section;
        continue;
      }
      let section = stageSection.get(stage);
      if (!section) {
        section = open(seq, stage);
        stageSection.set(stage, section);
      }
      section.lines.push(trimmed);
      lastTagged = section;
      continue;
    }

    const match = trimmed.match(SECTION_RE);
    if (match) {
      current = open(seq, match[1].trim());
      lastTagged = null; // an untagged banner means the stages have joined
      continue;
    }

    if (lastTagged) {
      lastTagged.lines.push(trimmed);
      continue;
    }
    if (!current) {
      current = open(seq, "Preparing scan");
    }
    current.lines.push(trimmed);
  }

  return sections;
}
