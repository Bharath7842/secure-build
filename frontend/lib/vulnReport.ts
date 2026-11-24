import type {
  VulnReportItem,
  VulnReportTrendPoint,
  VulnScanType,
  VulnSeverity,
  VulnStatus,
} from "@/lib/types";

export const SEVERITIES: VulnSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const SCAN_TYPES: VulnScanType[] = ["sast", "sca", "sbom", "dast"];
export const OPEN_STATUSES: VulnStatus[] = ["needs_triage", "confirmed"];

export const SEVERITY_LABEL: Record<VulnSeverity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Info",
};

/** Pill colours, the same scale the scan detail pages use. */
export const SEVERITY_PILL: Record<VulnSeverity, string> = {
  CRITICAL: "border-red-200 bg-red-50 text-red-700",
  HIGH: "border-orange-200 bg-orange-50 text-orange-700",
  MEDIUM: "border-amber-200 bg-amber-50 text-amber-700",
  LOW: "border-blue-200 bg-blue-50 text-blue-700",
  INFO: "border-slate-200 bg-slate-50 text-slate-600",
};

/** Solid colours for bars and chart series. */
export const SEVERITY_FILL: Record<VulnSeverity, string> = {
  CRITICAL: "#b91c1c",
  HIGH: "#ea580c",
  MEDIUM: "#d97706",
  LOW: "#2563eb",
  INFO: "#94a3b8",
};

export const STATUS_LABEL: Record<VulnStatus, string> = {
  needs_triage: "Needs triage",
  confirmed: "Confirmed",
  dismissed: "Dismissed",
  resolved: "Resolved",
  risk_accepted: "Risk accepted",
  fixed: "Fixed",
};

export const STATUS_HINT: Record<VulnStatus, string> = {
  needs_triage: "Still detected; nobody has decided whether it is real.",
  confirmed: "Still detected and confirmed as a real issue.",
  dismissed: "Marked as a false positive by the scanner or a reviewer.",
  resolved: "A reviewer marked it as fixed.",
  risk_accepted: "A reviewer accepted the risk.",
  fixed: "No longer detected by the latest scan.",
};

export const STATUS_PILL: Record<VulnStatus, string> = {
  needs_triage: "border-amber-200 bg-amber-50 text-amber-800",
  confirmed: "border-red-200 bg-red-50 text-red-700",
  dismissed: "border-slate-200 bg-slate-50 text-slate-600",
  resolved: "border-emerald-200 bg-emerald-50 text-emerald-700",
  risk_accepted: "border-violet-200 bg-violet-50 text-violet-700",
  fixed: "border-emerald-200 bg-emerald-50 text-emerald-700",
};

export const STATUS_FILL: Record<VulnStatus, string> = {
  needs_triage: "#f59e0b",
  confirmed: "#dc2626",
  dismissed: "#cbd5e1",
  resolved: "#10b981",
  risk_accepted: "#8b5cf6",
  fixed: "#059669",
};

export const SCAN_TYPE_LABEL: Record<VulnScanType, string> = {
  sast: "SAST",
  sca: "SCA",
  sbom: "SBOM",
  dast: "DAST",
};

export const SCAN_TYPE_HINT: Record<VulnScanType, string> = {
  sast: "Source code",
  sca: "Vulnerable dependencies",
  sbom: "License risk",
  dast: "Running application",
};

export const GRADE_HINT: Record<string, string> = {
  A: "No open critical or high issues.",
  B: "No open critical issues and at most 3 high.",
  C: "No open critical issues, but more than 3 high.",
  D: "1–2 open critical issues.",
  F: "3 or more open critical issues.",
};

export const GRADE_STYLE: Record<string, string> = {
  A: "bg-emerald-600",
  B: "bg-lime-600",
  C: "bg-amber-500",
  D: "bg-orange-600",
  F: "bg-red-700",
};

/** Rules shown in the security-grade help tooltip (must match `vulnerability_report._grade`). */
export const GRADE_RULES: { grade: string; rule: string }[] = [
  { grade: "A", rule: "No open Critical and no open High issues" },
  { grade: "B", rule: "No open Critical; at most 3 open High" },
  { grade: "C", rule: "No open Critical; more than 3 open High" },
  { grade: "D", rule: "1–2 open Critical issues" },
  { grade: "F", rule: "3 or more open Critical issues" },
];

export const GRADE_SCOPE_NOTE =
  "Only open Critical and High issues count. Medium, Low and Info do not change the grade. Fixed, resolved, risk accepted and dismissed issues are excluded. Needs triage and confirmed both count as open.";

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function formatDays(days: number | null | undefined): string {
  if (days == null) return "—";
  if (days < 1) return "< 1 day";
  const rounded = Math.round(days);
  return `${rounded} day${rounded === 1 ? "" : "s"}`;
}

export function formatPercent(value: number | null | undefined): string {
  return value == null ? "—" : `${Math.round(value * 100)}%`;
}

/** Open issues over time for every tool together: at each scan, the latest open count of each tool, summed. */
export function combinedOpenSeries(points: VulnReportTrendPoint[]): { point: VulnReportTrendPoint; open: number }[] {
  const latest: Partial<Record<VulnScanType, number>> = {};
  return points.map((point) => {
    latest[point.scan_type] = point.open;
    const open = Object.values(latest).reduce((a, b) => a + (b ?? 0), 0);
    return { point, open };
  });
}

function csvCell(value: unknown): string {
  const text = value == null ? "" : String(value);
  // A leading formula character would run as a formula when opened in a spreadsheet.
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export function vulnerabilitiesCsv(items: VulnReportItem[]): string {
  const header = [
    "Status", "Severity", "Tool", "Title", "CWE", "OWASP", "File", "Line", "Rule",
    "Occurrences", "Open occurrences", "Files", "Locations", "First detected", "First scan", "Last detected", "Last scan", "Fixed in scan", "Fixed at",
    "Age (days)", "Detections", "Overdue", "Reintroduced", "Still detected", "Reviewer", "Review comment",
  ];
  const rows = items.map((v) => [
    STATUS_LABEL[v.status], SEVERITY_LABEL[v.severity], SCAN_TYPE_LABEL[v.scan_type], v.title, v.cwe, v.owasp,
    v.file_path, v.line, v.rule_id, v.member_count, v.open_count, v.file_count,
    v.locations.map((l) => `${l.file_path ?? ""}${l.line ? `:${l.line}` : ""}`).join("; "), v.first_detected_at, `v${v.first_scan_version}`, v.last_detected_at,
    `v${v.last_scan_version}`, v.fixed_in_version ? `v${v.fixed_in_version}` : "", v.fixed_at, v.age_days,
    v.detections, v.overdue ? "yes" : "no", v.reintroduced ? "yes" : "no", v.still_detected ? "yes" : "no",
    v.review?.reviewer, v.review?.comment,
  ]);
  return [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
}

export function downloadText(filename: string, text: string, type = "text/csv;charset=utf-8") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
