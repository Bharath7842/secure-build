"use client";

import type { ScanLimitation } from "@/lib/types";

const CATEGORY_LABELS: Record<string, string> = {
  "engine-cap": "Engine Cap",
  "analysis-check": "Analysis Check",
  "security-pattern": "Security Pattern",
};

function InfoIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      className="text-blue-600"
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  );
}

interface ScanLimitationsPanelProps {
  limitations: ScanLimitation[];
  selectedIds: Set<string>;
  onChange: (ids: Set<string>) => void;
  disabled?: boolean;
}

export default function ScanLimitationsPanel({
  limitations,
  selectedIds,
  onChange,
  disabled = false,
}: ScanLimitationsPanelProps) {
  const handleToggle = (id: string) => {
    const newIds = new Set(selectedIds);
    if (newIds.has(id)) {
      newIds.delete(id);
    } else {
      newIds.add(id);
    }
    onChange(newIds);
  };

  const byCategory = limitations.reduce(
    (acc, lim) => {
      if (!acc[lim.category]) acc[lim.category] = [];
      acc[lim.category].push(lim);
      return acc;
    },
    {} as Record<string, ScanLimitation[]>
  );

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
          Scan Configuration
        </h2>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Enable or disable specific scan checks. Disabled checks will be skipped during the scan.
        </p>
      </div>

      {Object.entries(byCategory).map(([category, items]) => (
        <div key={category} className="border-t border-gray-200 dark:border-gray-700 pt-4">
          <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-3 flex items-center gap-2">
            <InfoIcon />
            {CATEGORY_LABELS[category] || category}
          </h3>

          <div className="space-y-3">
            {items.map((limitation) => (
              <label
                key={limitation.id}
                className="flex items-start gap-3 p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-900/30 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={selectedIds.has(limitation.id)}
                  onChange={() => handleToggle(limitation.id)}
                  disabled={disabled}
                  className="mt-1 w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-2">
                    <p className="font-medium text-gray-900 dark:text-white">
                      {limitation.title}
                    </p>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                    {limitation.description}
                  </p>
                  {limitation.affected_scope && (
                    <p className="text-xs text-gray-500 dark:text-gray-500 mt-2">
                      <span className="font-medium">Affected:</span> {limitation.affected_scope}
                    </p>
                  )}
                  {limitation.source && (
                    <p className="text-xs text-gray-500 dark:text-gray-500 mt-1 font-mono">
                      {limitation.source}
                    </p>
                  )}
                </div>
              </label>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
