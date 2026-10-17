"use client";

import { useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";

import { formatWhen } from "@/components/admin/badges";
import PageContainer from "@/components/PageContainer";
import type { AuditEvent } from "@/lib/access";
import { ApiError, api } from "@/lib/api";
import { inputClass, selectClass } from "@/lib/formStyles";

type Filters = { actor: string; action: string; outcome: string };

const ACTION_GROUPS = [
  ["", "All events"],
  ["auth.", "Sign-ins and sign-outs"],
  ["user.", "User and access changes"],
  ["scan.", "Scans"],
  ["admin.", "Setup"],
  ["schedule.", "Scheduled scans"],
] as const;

function summarize(details: Record<string, unknown>): string {
  return Object.entries(details)
    .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

export default function AuditLogPage() {
  const initialActor = useSearchParams().get("actor") ?? "";
  const [filters, setFilters] = useState<Filters>({ actor: initialActor, action: "", outcome: "" });
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [nextCursor, setNextCursor] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const timer = setTimeout(() => {
      api.admin
        .audit(filters)
        .then((page) => {
          if (!active) return;
          setEvents(page.items);
          setNextCursor(page.next_cursor);
          setError(null);
        })
        .catch((err) => active && setError(err instanceof ApiError ? err.message : "Could not load the audit log."));
    }, 250);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [filters]);

  async function loadMore() {
    if (nextCursor === null) return;
    try {
      const page = await api.admin.audit({ ...filters, cursor: nextCursor });
      setEvents((prev) => [...(prev ?? []), ...page.items]);
      setNextCursor(page.next_cursor);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load more events.");
    }
  }

  return (
    <PageContainer>
      <h1 className="font-display text-3xl text-[var(--ink)]">Audit log</h1>
      <p className="mt-2 max-w-3xl text-sm text-[var(--muted)]">
        Sign-ins, account and access changes, and scan starts, stops and deletions, newest first. Passwords, tokens and
        links are never recorded.
      </p>

      <div className="mt-8 flex flex-wrap items-end gap-4" role="search">
        <label className="block w-full max-w-xs text-sm">
          <span className="text-[var(--muted)]">Who</span>
          <input
            type="search"
            className={inputClass}
            placeholder="Email or user id"
            value={filters.actor}
            onChange={(e) => setFilters((f) => ({ ...f, actor: e.target.value }))}
          />
        </label>
        <label className="block text-sm">
          <span className="text-[var(--muted)]">Event</span>
          <select className={selectClass} value={filters.action} onChange={(e) => setFilters((f) => ({ ...f, action: e.target.value }))}>
            {ACTION_GROUPS.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="block text-sm">
          <span className="text-[var(--muted)]">Outcome</span>
          <select className={selectClass} value={filters.outcome} onChange={(e) => setFilters((f) => ({ ...f, outcome: e.target.value }))}>
            <option value="">Any</option>
            <option value="success">Succeeded</option>
            <option value="failure">Failed</option>
            <option value="denied">Denied</option>
          </select>
        </label>
      </div>

      {error && (
        <div role="alert" className="mt-6 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {events === null && !error ? (
        <p className="mt-10 text-sm text-[var(--muted)]">Loading…</p>
      ) : events && events.length === 0 ? (
        <div className="mt-10 rounded-md border border-slate-200 bg-white/60 px-6 py-10 text-center text-sm text-[var(--muted)]">
          No events match these filters. Try another event type or clear the search.
        </div>
      ) : events ? (
        <div className="mt-8 overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[var(--muted)]">
                <th className="py-2 pr-4 font-medium">When</th>
                <th className="py-2 pr-4 font-medium">Who</th>
                <th className="py-2 pr-4 font-medium">Event</th>
                <th className="py-2 pr-4 font-medium">Outcome</th>
                <th className="py-2 pr-4 font-medium">Target</th>
                <th className="py-2 pr-4 font-medium">Details</th>
                <th className="py-2 font-medium">Address</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className="border-b border-slate-100 align-top">
                  <td className="whitespace-nowrap py-2 pr-4 text-[var(--muted)]">{formatWhen(e.at)}</td>
                  <td className="py-2 pr-4">{e.actor_label || "system"}</td>
                  <td className="py-2 pr-4">
                    <code className="text-xs">{e.action}</code>
                  </td>
                  <td className={`py-2 pr-4 ${e.outcome === "success" ? "text-[var(--muted)]" : "font-medium text-red-700"}`}>
                    {e.outcome}
                  </td>
                  <td className="whitespace-nowrap py-2 pr-4 text-xs text-[var(--muted)]" title={e.target_id ?? undefined}>
                    {e.target_type ? `${e.target_type} ${(e.target_id ?? "").slice(0, 8)}` : "—"}
                  </td>
                  <td className="max-w-md break-words py-2 pr-4 text-xs text-[var(--muted)]">{summarize(e.details) || "—"}</td>
                  <td className="py-2 text-xs text-[var(--muted)]">{e.ip ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {nextCursor !== null && (
            <button type="button" onClick={loadMore} className="mt-4 text-sm font-medium text-[var(--accent)]">
              Show more
            </button>
          )}
        </div>
      ) : null}
    </PageContainer>
  );
}
