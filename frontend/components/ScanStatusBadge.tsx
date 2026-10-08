import type { Scan } from "@/lib/types";

/** Status accents use blue + emerald only. */
const STATUS_STYLES: Record<string, string> = {
  queued: "border-blue-100 bg-blue-50 text-blue-600",
  running: "border-blue-200 bg-blue-50 text-blue-700",
  success: "border-emerald-200 bg-emerald-50 text-emerald-700",
  failed: "border-blue-300 bg-blue-100 text-blue-800",
  cancelled: "border-blue-200 bg-blue-50 text-blue-700",
};

const STATUS_LABELS: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  success: "Success",
  failed: "Failed",
  cancelled: "Cancelled",
};

interface ScanStatusBadgeProps {
  status: Scan["status"];
}

function StatusIcon({ status }: { status: string }) {
  const common = {
    xmlns: "http://www.w3.org/2000/svg",
    width: 12,
    height: 12,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2.5,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true as const,
  };

  if (status === "success") {
    return (
      <svg {...common}>
        <path d="M20 6 9 17l-5-5" />
      </svg>
    );
  }
  if (status === "running") {
    return (
      <svg {...common} className="animate-spin">
        <path d="M21 12a9 9 0 1 1-6.2-8.6" />
      </svg>
    );
  }
  if (status === "failed") {
    return (
      <svg {...common}>
        <path d="M18 6 6 18M6 6l12 12" />
      </svg>
    );
  }
  if (status === "cancelled") {
    return (
      <svg {...common}>
        <circle cx="12" cy="12" r="10" />
        <path d="M8 12h8" />
      </svg>
    );
  }
  return (
    <svg {...common}>
      <circle cx="12" cy="12" r="10" />
      <path d="M12 8v4M12 16h.01" />
    </svg>
  );
}

export default function ScanStatusBadge({ status }: ScanStatusBadgeProps) {
  const style = STATUS_STYLES[status] ?? "border-blue-100 bg-blue-50 text-blue-600";
  const label = STATUS_LABELS[status] ?? status;

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${style}`}
    >
      <StatusIcon status={status} />
      {label}
    </span>
  );
}
