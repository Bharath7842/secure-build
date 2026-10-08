"use client";

import { useEffect, useState } from "react";

import { RoleBadge } from "@/components/DastAuthzPreview";
import { api } from "@/lib/api";
import type { DastAuthzCell, DastAuthzIdentity, DastAuthzMatrix, DastRoleName } from "@/lib/types";

const ROLE_NAMES: DastRoleName[] = ["admin", "user", "viewer", "anonymous", "custom"];

function roleName(value: string): DastRoleName {
  return (ROLE_NAMES as string[]).includes(value) ? (value as DastRoleName) : "custom";
}

function cellText(cell: DastAuthzCell): string {
  if (cell.result === "FAIL") return `${cell.failures} FAIL`;
  return cell.result === "OK" ? "OK" : "Not tested";
}

const CELL_TONE: Record<DastAuthzCell["result"], string> = {
  FAIL: "border-red-200 bg-red-50 text-red-800 hover:bg-red-100",
  OK: "border-emerald-200 bg-emerald-50 text-emerald-800",
  untested: "border-slate-200 bg-slate-100 text-slate-600",
};

function AccountName({
  label,
  role,
  custom,
  align = "left",
}: {
  label: string;
  role: string;
  custom?: string;
  align?: "left" | "center";
}) {
  const anon = roleName(role) === "anonymous";
  return (
    <div className={align === "center" ? "text-center" : "text-left"}>
      <p className="truncate text-sm font-medium text-[var(--ink)]">{anon ? "Not signed in" : label}</p>
      <div className={align === "center" ? "mt-0.5 flex justify-center" : "mt-0.5"}>
        <RoleBadge role={roleName(role)} customName={custom} />
      </div>
    </div>
  );
}

function cellDescription(owner: string, actor: string, cell: DastAuthzCell, active: boolean): string {
  if (cell.result === "FAIL") {
    return `${cell.failures} of ${owner}'s requests also succeeded as ${actor}. ${active ? "Click to stop filtering findings." : "Click to show those findings."}`;
  }
  if (cell.result === "OK") {
    return `Every ${owner} request was refused as ${actor}, which is what we want.`;
  }
  return cell.reason || "This pair was not tested.";
}

interface DastAuthzMatrixProps {
  scanId: string;
  live: boolean;
  selected: string | null;
  onSelect: (pair: string | null) => void;
  onClose: () => void;
}

/** Role-by-role access grid (DAST-14-020). One signed-in account is shown as a
 *  signed-in vs not-signed-in comparison; two or more accounts use the full matrix. */
export default function DastAuthzMatrixPanel({ scanId, live, selected, onSelect, onClose }: DastAuthzMatrixProps) {
  const [matrix, setMatrix] = useState<DastAuthzMatrix | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const data = await api.scans.authzMatrix(scanId);
        if (!active) return;
        setMatrix(data);
        setError(null);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Could not load authorization results.");
      }
    }
    load();
    if (!live) return () => { active = false; };
    const timer = setInterval(load, 2000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [scanId, live]);

  const owners = matrix?.identities ?? [];
  const columns = matrix
    ? [
        ...owners.map((i) => ({ label: i.label, role: i.role.name, custom: i.role.label })),
        { label: matrix.baseline_identity, role: "anonymous" as DastRoleName, custom: undefined },
      ]
    : [];
  const byPair = new Map((matrix?.cells ?? []).map((c) => [`${c.owner}:${c.actor}`, c]));

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden border-l border-slate-200 bg-white">
      <div className="flex shrink-0 items-center justify-between gap-3 border-b border-slate-200 px-4 py-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-[var(--ink)]">Authorization</h2>
          <p className="text-xs text-[var(--muted)]">Could another account use this account&apos;s requests?</p>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close authorization"
          className="agent-focus-ring rounded-md px-2 py-1 text-sm text-[var(--muted)] hover:bg-slate-100"
        >
          ✕
        </button>
      </div>
      <div className="min-h-0 flex-1 space-y-4 overflow-auto px-4 py-4">
        {error && (
          <p role="alert" className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </p>
        )}
        {!matrix && !error && <p className="text-sm text-[var(--muted)]">Loading authorization results…</p>}
        {matrix && owners.length === 0 && (
          <p className="rounded-md border border-slate-200 bg-slate-50 px-3 py-3 text-sm text-[var(--muted)]">
            This scan had no signed-in account, so there is nothing to compare. Add an identity when you start a scan
            to test access control.
          </p>
        )}
        {matrix && owners.length === 1 && (
          <SingleAccount
            owner={owners[0]}
            cell={byPair.get(`${owners[0].label}:${matrix.baseline_identity}`) ?? null}
            guestLabel={matrix.baseline_identity}
            replays={matrix.replays}
            ran={matrix.ran}
            live={live}
            selected={selected}
            onSelect={onSelect}
          />
        )}
        {matrix && owners.length > 1 && (
          <FullMatrix
            owners={owners}
            columns={columns}
            byPair={byPair}
            replays={matrix.replays}
            ran={matrix.ran}
            live={live}
            selected={selected}
            onSelect={onSelect}
          />
        )}
      </div>
    </div>
  );
}

function SingleAccount({
  owner,
  cell,
  guestLabel,
  replays,
  ran,
  live,
  selected,
  onSelect,
}: {
  owner: DastAuthzIdentity;
  cell: DastAuthzCell | null;
  guestLabel: string;
  replays: number;
  ran: boolean;
  live: boolean;
  selected: string | null;
  onSelect: (pair: string | null) => void;
}) {
  const pair = `${owner.label}:${guestLabel}`;
  const result = cell ?? { owner: owner.label, actor: guestLabel, result: "untested" as const, failures: 0, reason: "", finding_ids: [], finding_keys: [] };
  const failing = result.result === "FAIL";
  const active = selected === pair;

  return (
    <div className="space-y-4">
      <p className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-950">
        Only <span className="font-medium">{owner.label}</span> was signed in, so we compared that account with a
        visitor who is not signed in. To compare two roles (for example Admin against User), add a second identity on
        the next scan.
      </p>
      {!ran && (
        <p className="text-xs text-[var(--muted)]">
          Authorization checks have not run yet{live ? " — this updates as they do." : "."}
        </p>
      )}
      <div className="flex flex-wrap items-stretch gap-3">
        <div className="min-w-[10rem] flex-1 rounded-md border border-slate-200 bg-slate-50/80 px-3 py-3">
          <p className="text-[11px] font-medium uppercase tracking-wide text-[var(--muted)]">Signed in</p>
          <div className="mt-1.5">
            <AccountName label={owner.label} role={owner.role.name} custom={owner.role.label} />
          </div>
        </div>
        <p className="self-center text-xs font-medium text-[var(--muted)]" aria-hidden>
          then tried the same requests
        </p>
        <div className="min-w-[10rem] flex-1 rounded-md border border-slate-200 bg-slate-50/80 px-3 py-3">
          <p className="text-[11px] font-medium uppercase tracking-wide text-[var(--muted)]">Not signed in</p>
          <div className="mt-1.5">
            <AccountName label={guestLabel} role="anonymous" />
          </div>
        </div>
      </div>
      <ResultCard
        ownerLabel={owner.label}
        actorLabel="a visitor who is not signed in"
        cell={result}
        failing={failing}
        active={active}
        pair={pair}
        onSelect={onSelect}
      />
      {replays > 0 && (
        <p className="text-xs text-[var(--muted)]">
          {replays} request{replays === 1 ? "" : "s"} replayed.
        </p>
      )}
    </div>
  );
}

function ResultCard({
  ownerLabel,
  actorLabel,
  cell,
  failing,
  active,
  pair,
  onSelect,
}: {
  ownerLabel: string;
  actorLabel: string;
  cell: DastAuthzCell;
  failing: boolean;
  active: boolean;
  pair: string;
  onSelect: (pair: string | null) => void;
}) {
  const body =
    cell.result === "FAIL"
      ? `${cell.failures} of ${ownerLabel}'s requests also succeeded as ${actorLabel}. That is a broken access check.`
      : cell.result === "OK"
        ? `Every replayed request was refused as ${actorLabel}, which is what we want.`
        : cell.reason || "This check has not run yet.";
  return (
    <div className={`rounded-md border px-3 py-3 ${CELL_TONE[cell.result]} ${active ? "ring-2 ring-red-400" : ""}`}>
      <p className="text-sm font-semibold">{cellText(cell)}</p>
      <p className="mt-1 text-sm">{body}</p>
      {failing && (
        <button
          type="button"
          aria-label={`${ownerLabel}'s requests tried without signing in: ${cellText(cell)}. ${active ? "Stop filtering findings." : "Show those findings."}`}
          aria-pressed={active}
          onClick={() => onSelect(active ? null : pair)}
          className="agent-focus-ring mt-3 rounded-md border border-red-300 bg-white px-3 py-1.5 text-xs font-semibold text-red-800 hover:bg-red-50"
        >
          {active ? "Clear findings filter" : "Show those findings"}
        </button>
      )}
    </div>
  );
}

function FullMatrix({
  owners,
  columns,
  byPair,
  replays,
  ran,
  live,
  selected,
  onSelect,
}: {
  owners: DastAuthzIdentity[];
  columns: { label: string; role: string; custom?: string }[];
  byPair: Map<string, DastAuthzCell>;
  replays: number;
  ran: boolean;
  live: boolean;
  selected: string | null;
  onSelect: (pair: string | null) => void;
}) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-[var(--ink)]">
        Read down the left for whose requests we recorded, then across for who we sent those same requests as. A red
        cell means the column account could reach the row account&apos;s data.
      </p>
      {!ran && (
        <p className="text-xs text-[var(--muted)]">
          Authorization checks have not run yet{live ? " — cells fill in as they do." : "."}
        </p>
      )}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[28rem] border-separate border-spacing-1.5 text-sm">
          <caption className="sr-only">
            Access control grid. Rows are whose requests we recorded. Columns are who we sent those requests as.
          </caption>
          <thead>
            <tr>
              <th scope="col" rowSpan={2} className="w-36 p-1 text-left align-bottom text-[11px] font-medium uppercase tracking-wide text-[var(--muted)]">
                Whose requests
              </th>
              <th
                scope="colgroup"
                colSpan={columns.length}
                className="p-1 text-center text-[11px] font-medium uppercase tracking-wide text-[var(--muted)]"
              >
                Tried as
              </th>
            </tr>
            <tr>
              {columns.map((col) => (
                <th key={col.label} scope="col" className="p-1 align-bottom">
                  <AccountName label={col.label} role={col.role} custom={col.custom} align="center" />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {owners.map((owner) => (
              <tr key={owner.identity_id}>
                <th scope="row" className="p-1 text-left align-middle">
                  <AccountName label={owner.label} role={owner.role.name} custom={owner.role.label} />
                </th>
                {columns.map((col) => {
                  if (col.label === owner.label) {
                    return (
                      <td key={col.label} className="p-1 text-center">
                        <span className="block rounded-md border border-dashed border-slate-200 px-2 py-3 text-[11px] text-[var(--muted)]">
                          Same account
                        </span>
                      </td>
                    );
                  }
                  const pair = `${owner.label}:${col.label}`;
                  const cell = byPair.get(pair);
                  if (!cell) {
                    return (
                      <td key={col.label} className="p-1 text-center text-xs text-[var(--muted)]">
                        —
                      </td>
                    );
                  }
                  const failing = cell.result === "FAIL";
                  const active = selected === pair;
                  const tipId = `tip-${owner.identity_id}-${col.label}`.replace(/\s+/g, "-");
                  const actorName = roleName(col.role) === "anonymous" ? "a visitor who is not signed in" : col.label;
                  return (
                    <td key={col.label} className="relative p-0 align-middle">
                      <div className="group relative">
                        <button
                          type="button"
                          aria-label={`${owner.label}'s requests tried as ${col.label}: ${cellText(cell)}`}
                          aria-describedby={tipId}
                          aria-pressed={failing ? active : undefined}
                          onClick={failing ? () => onSelect(active ? null : pair) : undefined}
                          className={`agent-focus-ring w-full rounded-md border px-2 py-3 text-center text-xs font-semibold ${CELL_TONE[cell.result]} ${active ? "ring-2 ring-red-400" : ""} ${failing ? "cursor-pointer" : "cursor-default"}`}
                        >
                          <span className="block">{cellText(cell)}</span>
                          {cell.result === "FAIL" && (
                            <span className="mt-0.5 block text-[10px] font-normal">Click to view</span>
                          )}
                          {cell.result === "OK" && (
                            <span className="mt-0.5 block text-[10px] font-normal">Refused, as expected</span>
                          )}
                        </button>
                        <span
                          id={tipId}
                          role="tooltip"
                          className="pointer-events-none absolute left-1/2 top-full z-10 mt-1 hidden w-52 -translate-x-1/2 rounded-md bg-slate-900 px-2 py-1.5 text-left text-[11px] font-normal text-white shadow-lg group-focus-within:block group-hover:block"
                        >
                          {cellDescription(owner.label, actorName, cell, active)}
                        </span>
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {replays > 0 && (
        <p className="text-xs text-[var(--muted)]">
          {replays} request{replays === 1 ? "" : "s"} replayed.
        </p>
      )}
      <ul className="space-y-1 text-xs text-[var(--muted)]">
        <li>
          <span className="font-semibold text-emerald-800">OK</span> — the other account was refused. That is the safe
          result.
        </li>
        <li>
          <span className="font-semibold text-red-800">3 FAIL</span> — three of the row account&apos;s requests also
          succeeded as the column account. Click the cell to see them.
        </li>
        <li>
          <span className="font-semibold text-slate-700">Not tested</span> — this pair did not run. Hover the cell for
          why.
        </li>
        <li>
          <span className="font-semibold text-slate-700">Same account</span> — we never replay an account as itself.
        </li>
      </ul>
    </div>
  );
}
