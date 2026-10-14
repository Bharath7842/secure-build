"use client";

import { toModulePath } from "@/lib/modulePath";
import type { Reachability } from "@/lib/types";

const STATUS_TEXT: Record<string, { label: string; detail: string; tone: string }> = {
  path: {
    label: "Reachable from request input",
    detail: "Code property graph dataflow: this value reaches the sink's argument.",
    tone: "border-rose-200 bg-rose-50/60 text-rose-900",
  },
  sanitized_path: {
    label: "Reachable through a sanitizer",
    detail: "Code property graph dataflow passes a known sanitizer call; it may be safe.",
    tone: "border-amber-200 bg-amber-50/60 text-amber-900",
  },
  entry_reachable: {
    label: "Called from an entry point",
    detail: "Call graph, method level: does not show which value reaches the sink.",
    tone: "border-slate-200 bg-slate-50 text-slate-800",
  },
};

function where(file: string, line: number): string {
  return `${toModulePath(file) || file}:${line}`;
}

export default function ReachabilityEvidence({ evidence }: { evidence: Reachability }) {
  const text = STATUS_TEXT[evidence.status] ?? STATUS_TEXT.entry_reachable;
  const steps = evidence.taint_path || [];
  const elided = (evidence.steps_total ?? steps.length) - steps.length;
  const methodLevel = evidence.status === "entry_reachable";
  return (
    <details className={`mt-2 rounded border px-2.5 py-2 text-xs ${text.tone}`}>
      <summary className="cursor-pointer select-none font-medium">
        {text.label}
        <span className="ml-1.5 font-mono font-normal text-[var(--muted)]">
          {methodLevel ? evidence.taint_path[0]?.method : evidence.source.code}
        </span>
      </summary>
      <p className="mt-1 text-[var(--muted)]">
        {text.detail} Sink kind: {evidence.sink_kind}
        {methodLevel && evidence.authenticated ? " (entry point has an auth annotation)" : ""}.
      </p>
      <ol className="mt-1.5 space-y-0.5">
        {steps.map((step, idx) => (
          <li key={`${step.file}:${step.line}:${idx}`} className="font-mono text-[var(--ink)]">
            <span className="text-[var(--muted)]">{idx + 1}.</span>{" "}
            {methodLevel && step.method ? `${step.method} → ` : ""}
            {step.code}{" "}
            <span className="text-[var(--muted)]">({where(step.file, step.line)})</span>
            {elided > 0 && idx === 2 && (
              <div className="text-[var(--muted)]">… {elided} intermediate step(s) omitted</div>
            )}
          </li>
        ))}
      </ol>
      {(evidence.sanitizers?.length ?? 0) > 0 && (
        <p className="mt-1.5">
          <span className="font-medium">Sanitizers on the path: </span>
          <span className="font-mono">
            {evidence.sanitizers!.map((s) => `${s.code} (${where(s.file, s.line)})`).join("; ")}
          </span>
        </p>
      )}
      {(evidence.guards?.length ?? 0) > 0 && (
        <p className="mt-1">
          <span className="font-medium">Conditions on the path: </span>
          <span className="font-mono">
            {evidence.guards!.map((g) => `${g.code} (${where(g.file, g.line)})`).join("; ")}
          </span>
        </p>
      )}
    </details>
  );
}
