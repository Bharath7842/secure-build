"use client";

import { useEffect, useId, useMemo, useState, type ReactNode } from "react";

import { api } from "@/lib/api";
import { normalizeSeverity, RISK_STYLES } from "@/lib/findingStyles";
import type { DastCatalogCheck, DastCatalogPack, DastEffectiveCheck } from "@/lib/types";

/** Catalog titles may include an edition year; the UI shows the pack name only. */
export function displayPackTitle(title: string): string {
  return title
    .replace(/\s*\((?:19|20)\d{2}\)/g, "")
    .replace(/\s+(?:19|20)\d{2}(?=\s|$)/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

interface DastRulePackPickerProps {
  projectId: string | null;
  /** Two authenticated identities were entered: cross-role checks can run in full. */
  hasSecondIdentity: boolean;
  oastConfigured: boolean;
  /** Packs to start from (a rescan); omitted = the project defaults. */
  initialPacks?: string[] | null;
  /** `null` = the project/global defaults; a list = exactly these packs for this scan. */
  onChange: (packs: string[] | null) => void;
}

type ModalView = { kind: "pack"; packId: string } | { kind: "selected" };

type ListedCheck = {
  id: string;
  title: string;
  description: string;
  severity: string;
  running: boolean;
  note: string;
};

function catalogIndex(checks: DastCatalogCheck[]): Map<string, DastCatalogCheck> {
  return new Map(checks.map((check) => [check.id, check]));
}

function listedFromCatalog(
  ids: string[],
  byId: Map<string, DastCatalogCheck>,
  effective: Map<string, DastEffectiveCheck>,
  packSelected: boolean,
): ListedCheck[] {
  return ids.map((id) => {
    const catalog = byId.get(id);
    const live = effective.get(id);
    const running = packSelected && (live ? Boolean(live.enabled) : catalog?.enabled_by_default !== false);
    let note = "";
    if (!packSelected) note = "This pack is not selected.";
    else if (!running) note = live?.notes[0] || "Off for this scan (opt-in or missing a dependency).";
    return {
      id,
      title: catalog?.title || live?.definition.title || id,
      description: catalog?.description || "",
      severity: live?.severity || catalog?.severity || "",
      running,
      note,
    };
  });
}

function CheckListModal({
  title,
  subtitle,
  items,
  filters,
  onClose,
}: {
  title: string;
  subtitle?: string;
  items: ListedCheck[];
  filters?: ReactNode;
  onClose: () => void;
}) {
  const headingId = useId();
  const running = items.filter((item) => item.running);
  const idle = items.filter((item) => !item.running);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4 py-8"
      role="dialog"
      aria-modal="true"
      aria-labelledby={headingId}
      onClick={onClose}
    >
      <div
        className="flex max-h-full w-full max-w-lg flex-col rounded-lg bg-white shadow-xl"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="border-b border-slate-200 px-5 py-4">
          <h2 id={headingId} className="font-display text-lg text-[var(--ink)]">
            {title}
          </h2>
          {subtitle && <p className="mt-1 text-sm text-[var(--muted)]">{subtitle}</p>}
          {filters}
          <p className="mt-1 text-xs text-[var(--muted)]">
            {running.length} will run
            {idle.length > 0 ? ` · ${idle.length} will not` : ""}
          </p>
        </div>
        <ul className="min-h-0 flex-1 overflow-y-auto px-5 py-3">
          {items.length === 0 ? (
            <li className="py-6 text-sm text-[var(--muted)]">No checks in this selection.</li>
          ) : (
            items.map((item) => {
              const severity = item.severity ? normalizeSeverity(item.severity, true) : "";
              return (
                <li key={item.id} className="border-b border-slate-100 py-2.5 last:border-0">
                  <div className="flex items-start justify-between gap-3">
                    <p className={`text-sm font-medium ${item.running ? "text-[var(--ink)]" : "text-[var(--muted)]"}`}>
                      {item.title}
                    </p>
                    <span className="flex shrink-0 items-center gap-1.5">
                      {severity && (
                        <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${RISK_STYLES[severity]?.chip ?? "bg-slate-100 text-slate-600"}`}>
                          {severity}
                        </span>
                      )}
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${item.running ? "bg-emerald-50 text-emerald-800" : "bg-slate-100 text-slate-500"}`}>
                        {item.running ? "Will run" : "Won't run"}
                      </span>
                    </span>
                  </div>
                  {item.description && <p className="mt-0.5 text-xs text-[var(--muted)]">{item.description}</p>}
                  {item.note && !item.running && <p className="mt-0.5 text-[11px] text-amber-800">{item.note}</p>}
                </li>
              );
            })
          )}
        </ul>
        <div className="border-t border-slate-200 px-5 py-3">
          <button
            type="button"
            autoFocus
            onClick={onClose}
            className="agent-focus-ring rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-[var(--ink)] hover:bg-slate-50"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

/** Choose which rule packs run (DAST-13-040): the packs and their descriptions come from the backend,
 *  start from the project defaults and can be overridden for this scan, with a live count of the
 *  checks that will run and a note for each one that is off by default or missing a dependency. */
export default function DastRulePackPicker({ projectId, hasSecondIdentity, oastConfigured, initialPacks, onChange }: DastRulePackPickerProps) {
  const uid = useId();
  const [packs, setPacks] = useState<DastCatalogPack[]>([]);
  const [catalogChecks, setCatalogChecks] = useState<DastCatalogCheck[]>([]);
  const [defaults, setDefaults] = useState<string[]>([]);
  const [selected, setSelected] = useState<string[]>(initialPacks ?? []);
  const [touched, setTouched] = useState(Boolean(initialPacks));
  const [checks, setChecks] = useState<DastEffectiveCheck[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [modal, setModal] = useState<ModalView | null>(null);

  // The packs and the project's defaults.
  useEffect(() => {
    let active = true;
    Promise.all([api.dast.catalog(), api.dast.rules.effective({ projectId: projectId ?? undefined, secondIdentity: hasSecondIdentity, oast: oastConfigured })])
      .then(([catalog, preview]) => {
        if (!active) return;
        setPacks(catalog.packs);
        setCatalogChecks(catalog.checks ?? []);
        setDefaults(preview.rule_set.packs);
        setSelected((current) => (touched ? current : preview.rule_set.packs));
        setChecks(preview.rule_set.checks);
        setError(null);
      })
      .catch((err) => active && setError(err instanceof Error ? err.message : "Could not load the rule packs."))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
    // `touched` is read only to keep a user's selection when the project changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId, hasSecondIdentity, oastConfigured]);

  // The check count for the current selection.
  useEffect(() => {
    if (!touched) return;
    let active = true;
    api.dast.rules
      .effective({ projectId: projectId ?? undefined, packs: selected, secondIdentity: hasSecondIdentity, oast: oastConfigured })
      .then((preview) => {
        if (!active) return;
        setChecks(preview.rule_set.checks);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [selected, touched, projectId, hasSecondIdentity, oastConfigured]);

  function toggle(packId: string) {
    const next = selected.includes(packId) ? selected.filter((p) => p !== packId) : [...selected, packId];
    setSelected(next);
    setTouched(true);
    onChange(next);
  }

  function resetToDefaults() {
    setSelected(defaults);
    setTouched(false);
    onChange(null);
    api.dast.rules
      .effective({ projectId: projectId ?? undefined, secondIdentity: hasSecondIdentity, oast: oastConfigured })
      .then((preview) => {
        setChecks(preview.rule_set.checks);
      })
      .catch(() => undefined);
  }

  const byCatalog = useMemo(() => catalogIndex(catalogChecks), [catalogChecks]);
  const byEffective = useMemo(() => new Map(checks.map((check) => [check.id, check])), [checks]);
  const enabled = checks.filter((c) => c.enabled);
  const notRun = checks.filter((c) => !c.enabled);

  const modalItems = useMemo(() => {
    if (!modal) return [];
    if (modal.kind === "pack") {
      const pack = packs.find((p) => p.id === modal.packId);
      return listedFromCatalog(pack?.check_ids ?? [], byCatalog, byEffective, selected.includes(modal.packId)).sort(
        (a, b) => Number(b.running) - Number(a.running) || a.title.localeCompare(b.title),
      );
    }
    const seen = new Set<string>();
    const items: ListedCheck[] = [];
    for (const pack of packs.filter((p) => selected.includes(p.id))) {
      for (const item of listedFromCatalog(pack.check_ids, byCatalog, byEffective, true)) {
        if (seen.has(item.id)) continue;
        seen.add(item.id);
        items.push(item);
      }
    }
    return items.sort((a, b) => Number(b.running) - Number(a.running) || a.title.localeCompare(b.title));
  }, [modal, packs, selected, byCatalog, byEffective]);

  const modalTitle =
    modal?.kind === "pack"
      ? displayPackTitle(packs.find((p) => p.id === modal.packId)?.title ?? "Checks")
      : "Selected checks";
  const modalSubtitle =
    modal?.kind === "pack"
      ? packs.find((p) => p.id === modal.packId)?.description
      : selected.length === 0
        ? "No rule pack is selected."
        : packs
            .filter((p) => selected.includes(p.id))
            .map((p) => displayPackTitle(p.title))
            .join(" · ");

  return (
    <fieldset className="space-y-3 rounded-md border border-slate-200 p-4">
      <legend className="px-1 text-sm font-medium text-[var(--ink)]">Rule packs</legend>
      {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
      {loading ? (
        <p className="text-sm text-[var(--muted)]">Loading rule packs…</p>
      ) : (
        <>
          <p className="text-xs text-[var(--muted)]">
            Pre-selected from {projectId ? "this project's defaults" : "the global defaults"}. Changes here apply to this scan only.
            Click a pack name to see its checks.
          </p>
          <ul className="space-y-2">
            {packs.map((pack) => (
              <li key={pack.id}>
                <div className="flex items-start gap-2.5 text-sm text-[var(--ink)]">
                  <input
                    id={`${uid}-${pack.id}`}
                    type="checkbox"
                    checked={selected.includes(pack.id)}
                    onChange={() => toggle(pack.id)}
                    className="mt-0.5 h-4 w-4 rounded border-slate-300 text-[var(--accent)] focus:ring-[var(--accent)]/30"
                  />
                  <div className="min-w-0 flex-1">
                    <button
                      type="button"
                      onClick={() => setModal({ kind: "pack", packId: pack.id })}
                      className="agent-focus-ring rounded-sm text-left"
                    >
                      <span className="font-medium hover:text-[var(--accent)] hover:underline">{displayPackTitle(pack.title)}</span>
                      <span className="text-[var(--muted)]"> · {pack.check_ids.length} check{pack.check_ids.length === 1 ? "" : "s"} in this pack</span>
                    </button>
                    {pack.description && <p className="text-xs text-[var(--muted)]">{pack.description}</p>}
                  </div>
                </div>
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <button
              type="button"
              onClick={() => setModal({ kind: "selected" })}
              className="agent-focus-ring rounded-sm text-sm font-medium text-[var(--ink)] hover:text-[var(--accent)] hover:underline"
              aria-live="polite"
              data-testid="check-count"
            >
              {enabled.length} unique check{enabled.length === 1 ? "" : "s"} will run
              {selected.length === 0 && " (no pack selected)"}
            </button>
            {touched && (
              <button type="button" onClick={resetToDefaults} className="text-xs font-medium text-[var(--accent)] hover:underline">
                Back to the defaults
              </button>
            )}
          </div>
          {selected.length > 1 && (
            <p className="text-xs text-[var(--muted)]">
              Pack totals are not added together: the same check can belong to multiple packs, so the scan runs one deduplicated check set.
            </p>
          )}
          {notRun.length > 0 && (
            <details className="rounded-md border border-slate-200 bg-slate-50/60 px-3 py-2 text-xs">
              <summary className="cursor-pointer font-medium text-[var(--ink)]">
                {notRun.length} check{notRun.length === 1 ? " is" : "s are"} off
              </summary>
              <ul className="mt-2 space-y-1.5 text-[var(--muted)]">
                {notRun.map((check) => (
                  <li key={check.id}>
                    <span className="font-medium text-[var(--ink)]">{check.definition.title}</span> — off by default or opt-in (load-generating checks stay
                    off until you enable them under DAST settings → Rule sets).
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
      {modal && (
        <CheckListModal
          title={modalTitle}
          subtitle={modal.kind === "pack" ? modalSubtitle : undefined}
          items={modalItems}
          filters={
            modal.kind === "selected" ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {packs.map((pack) => (
                  <label
                    key={pack.id}
                    className={`flex cursor-pointer items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs ${
                      selected.includes(pack.id)
                        ? "border-[var(--accent)] bg-blue-50 text-[var(--ink)]"
                        : "border-slate-200 bg-white text-[var(--muted)]"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={selected.includes(pack.id)}
                      onChange={() => toggle(pack.id)}
                      className="h-3.5 w-3.5 rounded border-slate-300 text-[var(--accent)] focus:ring-[var(--accent)]/30"
                    />
                    {displayPackTitle(pack.title)}
                  </label>
                ))}
              </div>
            ) : undefined
          }
          onClose={() => setModal(null)}
        />
      )}
    </fieldset>
  );
}
