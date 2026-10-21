"use client";

import { useState } from "react";

import { api } from "@/lib/api";
import { describeVerdictChange, formatWhen, STAGE_LABEL } from "@/lib/review";
import type { FindingHistoryEntry } from "@/lib/types";
import { unresolvedReasonLabel } from "@/lib/verdict";

type Props = { scanId: string; findingId: string };

function evidenceNote(entry: FindingHistoryEntry): string | null {
  const evidence = entry.evidence_version;
  if (!evidence) return null;
  const parts: string[] = [];
  const commit = evidence.engine_commit;
  if (typeof commit === "string" && commit !== "unknown" && commit !== "mock") {
    parts.push(`engine ${commit.slice(0, 7)}`);
  }
  const model = evidence.llm_model;
  if (typeof model === "string" && model) parts.push(model);
  if (evidence.result_cache_hit === true) parts.push("replayed from the result cache");
  return parts.length ? parts.join(" · ") : null;
}

/** Every verdict the scanner gave this finding (and each reviewer decision), in time order.
 *  Loaded when first opened: most findings are never inspected this closely. */
export default function FindingDecisionHistory({ scanId, findingId }: Props) {
  const [entries, setEntries] = useState<FindingHistoryEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  function load() {
    if (entries !== null) return;
    api.scans
      .findingHistory(scanId, findingId)
      .then((history) => setEntries(history.entries))
      .catch(() => setError("Could not load the decision history."));
  }

  return (
    <details
      className="mt-2 text-xs"
      onToggle={(event) => {
        if ((event.currentTarget as HTMLDetailsElement).open) load();
      }}
    >
      <summary className="cursor-pointer text-[var(--muted)]">
        Decision history{entries ? ` (${entries.length})` : ""}
      </summary>
      {error ? <p className="mt-1.5 text-red-700">{error}</p> : null}
      {!error && entries === null ? <p className="mt-1.5 text-[var(--muted)]">Loading…</p> : null}
      {entries && entries.length === 0 ? (
        <p className="mt-1.5 text-[var(--muted)]">No decisions recorded for this finding.</p>
      ) : null}
      {entries && entries.length > 0 ? (
        <ol className="mt-1.5 space-y-1.5 border-l border-slate-200 pl-3">
          {entries.map((entry, index) => {
            const note = evidenceNote(entry);
            const why = unresolvedReasonLabel(entry.unresolved_reason);
            return (
              <li key={`${entry.source}-${entry.at}-${index}`}>
                <div>
                  <span className="font-medium">
                    {entry.source === "machine"
                      ? (STAGE_LABEL[entry.actor ?? ""] ?? entry.actor ?? "Scanner")
                      : (entry.actor ?? "Reviewer")}
                  </span>{" "}
                  <span className="text-[var(--muted)]">
                    ({entry.source === "machine" ? "scanner" : "reviewer"})
                  </span>
                  : {describeVerdictChange(entry)}
                  {why ? <span className="text-[var(--muted)]"> — {why}</span> : null}
                </div>
                {entry.reason ? (
                  <div className="whitespace-pre-wrap text-[var(--muted)]">“{entry.reason}”</div>
                ) : null}
                <div className="text-[var(--muted)]">
                  {formatWhen(entry.at)}
                  {note ? ` · ${note}` : ""}
                </div>
              </li>
            );
          })}
        </ol>
      ) : null}
    </details>
  );
}
