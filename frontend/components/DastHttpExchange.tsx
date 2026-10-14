"use client";

import type { ReactNode } from "react";

import type { DastTraffic } from "@/lib/types";

function httpStatus(excerpt: string | null | undefined): string | null {
  const match = /(?:HTTP\/[\d.]+ |HTTP )?(\d{3})\b/.exec(excerpt ?? "");
  return match ? `HTTP ${match[1]}` : null;
}

function HeaderMap({ headers }: { headers: Record<string, string> }) {
  const entries = Object.entries(headers).slice(0, 16);
  if (entries.length === 0) return null;
  return (
    <dl className="mt-1 space-y-0.5 font-mono text-[11px] text-[var(--ink)]">
      {entries.map(([key, value]) => (
        <div key={key} className="flex gap-2">
          <dt className="shrink-0 text-[var(--muted)]">{key}:</dt>
          <dd className="min-w-0 break-all">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function Block({ title, status, children }: { title: string; status?: string | null; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <p className="text-xs font-medium text-[var(--ink)]">
        {title}
        {status && <span className="ml-1.5 font-mono font-normal text-[var(--muted)]">{status}</span>}
      </p>
      <div className="mt-1 max-h-56 overflow-auto rounded bg-slate-50 p-2">{children}</div>
    </div>
  );
}

export function trafficFromTarget(
  target: string | null | undefined,
  extras: {
    parameter?: string | null;
    location?: string | null;
    payload?: string | null;
    seq?: string | number | null;
    responseStatus?: number | null;
    url?: string | null;
  } = {},
) {
  const bits = (target || "").split(/\s+/);
  const method = bits[0] && /^[A-Za-z]{2,10}$/.test(bits[0]) ? bits[0].toUpperCase() : "";
  const path = method ? bits.slice(1).join(" ") : target || "";
  return trafficFromParts({
    method,
    url: extras.url || path,
    parameter: extras.parameter,
    location: extras.location,
    payload: extras.payload,
    seq: extras.seq,
    responseStatus: extras.responseStatus,
  });
}

export function trafficFromParts(parts: {
  method?: string;
  url?: string;
  parameter?: string | null;
  location?: string | null;
  payload?: string | null;
  seq?: string | number | null;
  responseStatus?: number | null;
}): DastTraffic {
  return {
    method: parts.method || "",
    url: parts.url || "",
    parameter: parts.parameter ?? null,
    location: parts.location ?? null,
    payload: parts.payload || "",
    seq: parts.seq == null || parts.seq === "" ? null : Number(parts.seq),
    response_status: parts.responseStatus ?? null,
  };
}

/** Request the scan sent and the response it got back. Empty sides are omitted. */
export default function DastHttpExchange({
  request,
  baseline,
  response,
  responseStatus,
  responseMeta,
  signals,
  proposedPayload,
  source,
}: {
  request?: DastTraffic | null;
  baseline?: string | null;
  response?: string | null;
  responseStatus?: number | null;
  responseMeta?: string | null;
  signals?: { name: string; detail?: string }[];
  proposedPayload?: string | null;
  source?: "model" | "fallback" | string | null;
}) {
  const hasRequest = Boolean(
    request && (request.method || request.url || request.payload || request.parameter || request.headers),
  );
  const hasBaseline = Boolean(baseline);
  const hasResponse = Boolean(response || responseStatus != null);
  if (!hasRequest && !hasBaseline && !hasResponse && !(signals && signals.length)) return null;

  const line = [request?.method, request?.url].filter(Boolean).join(" ");
  const status =
    responseStatus != null
      ? `HTTP ${responseStatus}`
      : request?.response_status != null
        ? `HTTP ${request.response_status}`
        : httpStatus(response);

  return (
    <div className="mt-2 space-y-2 rounded border border-slate-200 bg-white p-2.5" aria-label="Request and response">
      <div className={`grid gap-2 ${hasRequest && (hasBaseline || hasResponse) ? "md:grid-cols-2" : ""}`}>
        {hasRequest && request && (
          <Block title="Request sent" status={request.allowed === false ? "not sent" : undefined}>
            {line && <pre className="whitespace-pre-wrap break-all font-mono text-[11px] text-[var(--ink)]">{line}</pre>}
            {request.identity_label && <p className="mt-1 text-[11px] text-[var(--muted)]">Identity: {request.identity_label}</p>}
            {source && <p className="mt-1 text-[11px] text-[var(--muted)]">Payload source: {source === "model" ? "LLM" : source}</p>}
            {request.allowed === false && (
              <p className="mt-1 text-[11px] text-amber-800">Not sent: {request.deny_reason || "denied"}</p>
            )}
            {request.parameter && (
              <p className="mt-1 text-[11px] text-[var(--ink)]">
                Parameter <span className="font-mono">{request.parameter}</span>
                {request.location && <span className="text-[var(--muted)]"> ({request.location})</span>}
              </p>
            )}
            {request.payload ? (
              <pre className="mt-1 whitespace-pre-wrap break-all font-mono text-[11px] text-[var(--ink)]">
                Value sent: {request.payload}
              </pre>
            ) : null}
            {proposedPayload && proposedPayload !== request.payload ? (
              <pre className="mt-1 whitespace-pre-wrap break-all font-mono text-[11px] text-[var(--ink)]">
                LLM proposal: {proposedPayload}
              </pre>
            ) : proposedPayload ? (
              <p className="mt-1 text-[11px] text-[var(--muted)]">LLM proposal: same as value sent</p>
            ) : null}
            {request.headers && <HeaderMap headers={request.headers} />}
          </Block>
        )}
        {hasBaseline && (
          <Block title="Baseline response" status={httpStatus(baseline)}>
            <pre className="whitespace-pre-wrap break-all font-mono text-[11px] text-[var(--ink)]">{baseline}</pre>
          </Block>
        )}
        {hasResponse && (
          <div className={`min-w-0 ${hasRequest && hasBaseline ? "md:col-span-2" : ""}`}>
            <Block title="Response received" status={status}>
              {responseMeta && <p className="mb-1 text-[11px] text-[var(--muted)]">{responseMeta}</p>}
              {request?.response_headers && <HeaderMap headers={request.response_headers} />}
              {response ? (
                <pre className="whitespace-pre-wrap break-all font-mono text-[11px] text-[var(--ink)]">{response}</pre>
              ) : (
                <p className="text-[11px] text-[var(--muted)]">No response body was stored.</p>
              )}
            </Block>
          </div>
        )}
      </div>
      {signals && signals.length > 0 ? (
        <div>
          <p className="text-xs font-medium text-[var(--ink)]">Detector signals</p>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {signals.map((signal, i) => (
              <li key={`${signal.name}-${i}`} className="rounded-full border border-sky-200 bg-sky-50 px-2 py-0.5 text-[11px] text-sky-900" title={signal.detail}>
                <span className="font-mono">{signal.name.startsWith("marker_") ? `Browser proof: ${signal.name}` : signal.name}</span>
                {signal.detail && <span className="text-sky-700"> — {signal.detail}</span>}
              </li>
            ))}
          </ul>
        </div>
      ) : signals ? (
        <p className="text-xs text-[var(--muted)]">No detector signal: this is a lead for a person to check, not proof.</p>
      ) : null}
    </div>
  );
}
