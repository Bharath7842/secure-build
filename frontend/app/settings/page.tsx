"use client";

import { useEffect, useState } from "react";

import PageContainer from "@/components/PageContainer";
import { ApiError, api } from "@/lib/api";
import type { ModelCatalog, ModelCatalogEntry } from "@/lib/types";
import { setModelCatalog } from "@/lib/useModelCatalog";

const DAST_PROVIDER_LABELS: Record<string, string> = {
  ollama: "Local (Ollama)",
  bedrock: "Amazon Bedrock",
  openai: "OpenAI",
  anthropic: "Anthropic",
  claude_cli: "Claude (local CLI)",
};

interface Group {
  id: string;
  title: string;
  description: string;
  models: ModelCatalogEntry[];
}

function groupsOf(catalog: ModelCatalog): Group[] {
  return [
    {
      id: "sast",
      title: "SAST models",
      description: "Offered when creating a project and when starting a SAST scan.",
      models: catalog.sast,
    },
    ...Object.entries(catalog.dast).map(([provider, models]) => ({
      id: `dast-${provider}`,
      title: `DAST — ${DAST_PROVIDER_LABELS[provider] ?? provider}`,
      description: "Offered in the DAST model picker and the DAST model routing settings.",
      models,
    })),
  ];
}

export default function SettingsPage() {
  const [catalog, setCatalog] = useState<ModelCatalog | null>(null);
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    let active = true;
    api.settings.models
      .get()
      .then((c) => {
        if (!active) return;
        setCatalog(c);
        setHidden(new Set(c.hidden));
      })
      .catch((err) => active && setError(err instanceof ApiError ? err.message : "Could not load model settings."));
    return () => {
      active = false;
    };
  }, []);

  const dirty = catalog !== null && [...hidden].sort().join("\n") !== [...catalog.hidden].sort().join("\n");

  function toggle(key: string) {
    setSaved(false);
    setHidden((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function setGroup(group: Group, show: boolean) {
    setSaved(false);
    setHidden((current) => {
      const next = new Set(current);
      for (const m of group.models) {
        if (show) next.delete(m.key);
        else next.add(m.key);
      }
      // The pinned local model can't be hidden.
      for (const m of group.models) if (m.pinned) next.delete(m.key);
      return next;
    });
  }

  async function save() {
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const next = await api.settings.models.update([...hidden]);
      setCatalog(next);
      setHidden(new Set(next.hidden));
      setModelCatalog(next);
      setSaved(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not save model settings.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <PageContainer>
      <div className="mx-auto max-w-4xl space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-[var(--ink)]">Settings</h1>
          <p className="mt-1 text-sm text-[var(--muted)]">
            Choose which models appear in the model selects. Hiding a model only removes it from the dropdowns: a
            project or scan that already uses it keeps working and still shows it. The local Ollama
            granite-code:3b-instruct is always available; everything else, including a whole provider, can be hidden.
          </p>
        </div>

        {error && (
          <p role="alert" className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </p>
        )}
        {!catalog && !error && (
          <p role="status" className="text-sm text-[var(--muted)]">
            Loading model settings…
          </p>
        )}

        {catalog &&
          groupsOf(catalog).map((group) => {
            const visibleCount = group.models.filter((m) => !hidden.has(m.key)).length;
            return (
              <section
                key={group.id}
                aria-labelledby={`${group.id}-heading`}
                className="rounded-lg border border-slate-200 bg-white p-6"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <h2 id={`${group.id}-heading`} className="text-base font-semibold text-[var(--ink)]">
                      {group.title}
                    </h2>
                    <p className="mt-0.5 text-xs text-[var(--muted)]">
                      {group.description} {visibleCount} of {group.models.length} shown.
                    </p>
                  </div>
                  <div className="flex gap-3 text-xs font-medium">
                    <button
                      type="button"
                      onClick={() => setGroup(group, true)}
                      className="text-[var(--accent)] hover:underline"
                    >
                      Show all
                    </button>
                    <button
                      type="button"
                      onClick={() => setGroup(group, false)}
                      className="text-[var(--accent)] hover:underline"
                    >
                      Hide all
                    </button>
                  </div>
                </div>
                <ul className="mt-3 divide-y divide-slate-100">
                  {group.models.map((m) => {
                    const checked = !hidden.has(m.key);
                    return (
                      <li key={m.key}>
                        <label className="flex cursor-pointer items-start gap-3 py-2.5">
                          <input
                            type="checkbox"
                            checked={checked}
                            disabled={m.pinned}
                            onChange={() => toggle(m.key)}
                            className="mt-0.5 h-4 w-4 rounded border-slate-300"
                          />
                          <span className="min-w-0">
                            <span className="block text-sm text-[var(--ink)]">{m.label}</span>
                            <span className="block break-all font-mono text-xs text-[var(--muted)]">
                              {m.provider} · {m.model}
                            </span>
                            {m.pinned && (
                              <span className="block text-xs text-[var(--muted)]">
                                Always available: the local default, so a select is never empty.
                              </span>
                            )}
                          </span>
                        </label>
                      </li>
                    );
                  })}
                </ul>
              </section>
            );
          })}

        {catalog && (
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={save}
              disabled={!dirty || saving}
              className="agent-focus-ring rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
            >
              {saving ? "Saving…" : "Save changes"}
            </button>
            {dirty && !saving && (
              <button
                type="button"
                onClick={() => setHidden(new Set(catalog.hidden))}
                className="text-sm font-medium text-[var(--accent)] hover:underline"
              >
                Discard
              </button>
            )}
            {saved && !dirty && (
              <span role="status" className="text-sm text-green-700">
                Saved. New choices apply to forms as you open them.
              </span>
            )}
          </div>
        )}
      </div>
    </PageContainer>
  );
}
