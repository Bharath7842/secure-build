"use client";

import { Fragment } from "react";

import { toModulePath } from "@/lib/modulePath";
import type { Reachability, ReachabilityStep } from "@/lib/types";

const STATUS_TEXT: Record<string, { label: string; detail: string; tone: string; badge: string }> = {
  path: {
    label: "Data flow: request input reaches the sink",
    detail: "Traced through each call's arguments, step by step.",
    tone: "border-rose-200 bg-rose-50/60 text-rose-900",
    badge: "bg-rose-600 text-white",
  },
  sanitized_path: {
    label: "Data flow: input reaches the sink through an encoder",
    detail: "Traced through each call's arguments; an encoder suited to this sink is on the path, so it may be safe.",
    tone: "border-amber-200 bg-amber-50/60 text-amber-900",
    badge: "bg-amber-500 text-white",
  },
  entry_reachable: {
    label: "Called from an entry point",
    detail: "Call graph, method level: does not show which value reaches the sink.",
    tone: "border-slate-200 bg-slate-50 text-slate-800",
    badge: "bg-slate-500 text-white",
  },
};

const SINK_LABEL: Record<string, string> = {
  sql: "SQL query",
  jpa: "SQL / JPA query",
  jdbc_template: "SQL query",
  command: "OS command",
  ssrf: "outbound request",
  files: "file path",
  xss: "HTTP response",
  redirect: "redirect / response header",
  ldap: "LDAP query",
  eval: "expression evaluation",
  deser: "deserialization",
  xxe: "XML parser",
  reflect: "reflection",
};

function where(file: string, line: number): string {
  return `${toModulePath(file) || file}:${line}`;
}

function stepTitle(index: number, last: boolean, methodLevel: boolean, sink: string): string {
  if (index === 0) return methodLevel ? "Entry point" : "Untrusted input enters";
  if (last) return `Reaches the sink · ${sink}`;
  return methodLevel ? "Calls" : "Passed on in a call";
}

function Step({
  step, number, title, badge, last,
}: { step: ReachabilityStep; number: number; title: string; badge: string; last: boolean }) {
  return (
    <li className="relative flex gap-2.5 pb-3 last:pb-0">
      {!last && <span aria-hidden className="absolute left-[11px] top-6 bottom-0 w-px bg-current opacity-25" />}
      <span
        className={`relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold ${badge}`}
      >
        {number}
      </span>
      <div className="min-w-0 flex-1 pt-0.5">
        <p className="font-medium">
          {title}
          {step.method ? (
            <span className="ml-1 font-normal text-[var(--muted)]">
              in <span className="font-mono">{step.method}</span>
            </span>
          ) : null}
        </p>
        <code className="mt-1 block overflow-x-auto whitespace-pre-wrap break-all rounded border border-black/5 bg-white/70 px-2 py-1 font-mono text-[var(--ink)]">
          {step.code}
        </code>
        <p className="mt-0.5 font-mono text-[11px] text-[var(--muted)]">{where(step.file, step.line)}</p>
      </div>
    </li>
  );
}

export default function ReachabilityEvidence({ evidence }: { evidence: Reachability }) {
  const text = STATUS_TEXT[evidence.status] ?? STATUS_TEXT.entry_reachable;
  const steps = evidence.taint_path || [];
  const total = evidence.steps_total ?? steps.length;
  const elided = total - steps.length;
  const methodLevel = evidence.status === "entry_reachable";
  const sink = SINK_LABEL[evidence.sink_kind] ?? evidence.sink_kind;
  // A long path keeps its first three steps and its tail; the tail keeps its
  // true step numbers.
  const headCount = elided > 0 ? 3 : steps.length;
  return (
    <details open={!methodLevel} className={`mt-2 rounded border px-2.5 py-2 text-xs ${text.tone}`}>
      <summary className="cursor-pointer select-none font-medium">
        {text.label}
        <span className="ml-1.5 font-normal text-[var(--muted)]">
          ({total} step{total === 1 ? "" : "s"} · {sink})
        </span>
      </summary>
      <p className="mt-1 text-[var(--muted)]">
        {text.detail}
        {methodLevel && evidence.authenticated ? " The entry point has an auth annotation." : ""}
      </p>
      <ol className="mt-2.5">
        {steps.map((step, idx) => {
          const number = idx < headCount ? idx + 1 : idx + 1 + elided;
          const last = idx === steps.length - 1;
          return (
            <Fragment key={`${step.file}:${step.line}:${idx}`}>
              {elided > 0 && idx === headCount && (
                <li className="mb-3 ml-8 text-[var(--muted)]">… {elided} intermediate step(s) omitted</li>
              )}
              <Step
                step={step}
                number={number}
                title={stepTitle(number - 1, last, methodLevel, sink)}
                badge={text.badge}
                last={last}
              />
            </Fragment>
          );
        })}
      </ol>
      {(evidence.sanitizers?.length ?? 0) > 0 && (
        <p className="mt-2">
          <span className="font-medium">Encoders on the path: </span>
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
