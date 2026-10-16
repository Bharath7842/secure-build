"use client";

import { useState } from "react";

import { DAST_MODEL_OPTIONS, defaultDastModel } from "@/lib/dastModels";
import { selectClass } from "@/lib/formStyles";
import type { DastModelChoice, DastModelProvider, DastModelTask, DastProviders, DastSettings } from "@/lib/types";
import { useModelCatalog } from "@/lib/useModelCatalog";

const TASKS: { task: DastModelTask; label: string }[] = [
  { task: "construct", label: "Test construction" },
  { task: "rule", label: "Verdict advice" },
  { task: "narrate", label: "Narration" },
  { task: "fingerprint", label: "Fingerprinting" },
  { task: "crawl_plan", label: "Crawl planning" },
  { task: "login_selectors", label: "Login selectors" },
];

export const PROVIDER_LABELS: Record<DastModelProvider, string> = {
  ollama: "Local (Ollama)",
  bedrock: "Amazon Bedrock",
  openai: "OpenAI",
  anthropic: "Anthropic",
};

const PROVIDERS = Object.keys(PROVIDER_LABELS) as DastModelProvider[];

interface DastModelPickerProps {
  settings: DastSettings | null;
  providers: DastProviders | null;
  /** Only the tasks changed for this scan. */
  value: Partial<Record<DastModelTask, DastModelChoice>>;
  onChange: (next: Partial<Record<DastModelTask, DastModelChoice>>) => void;
}

function ModelSelect({
  id,
  provider,
  model,
  onChange,
}: {
  id: string;
  provider: DastModelProvider;
  model: string;
  onChange: (model: string) => void;
}) {
  const { dastOptions } = useModelCatalog();
  const options = dastOptions(provider, model);
  const known = options.some((o) => o.id === model);
  const selectValue = known ? model : model ? "__custom" : options[0]?.id ?? "";
  return (
    <div>
      <select
        id={id}
        value={selectValue === "__custom" ? model : selectValue}
        onChange={(e) => onChange(e.target.value)}
        className={selectClass.replace("mt-1.5", "mt-0")}
      >
        {options.map((o) => (
          <option key={o.id} value={o.id}>
            {o.label}
          </option>
        ))}
        {!known && model && <option value={model}>{model}</option>}
      </select>
    </div>
  );
}

/** Provider and model for this scan (DAST-13-040), defaulting to the configured routing. Switching
 *  the provider to Bedrock fills Claude Haiku. A provider without credentials is flagged before submit. */
export default function DastModelPicker({ settings, providers, value, onChange }: DastModelPickerProps) {
  const { dastOptions, dastProviders } = useModelCatalog();
  const defaults = new Map((settings?.model_routing ?? []).map((r) => [r.task, r]));
  const configured = new Map((providers?.providers ?? []).map((p) => [p.provider, p.configured]));
  const changed = Object.keys(value).length;
  const [showPerTask, setShowPerTask] = useState(false);

  function currentFor(task: DastModelTask): DastModelChoice {
    const base = defaults.get(task);
    return value[task] ?? (base ? { provider: base.provider, model: base.model } : { provider: "ollama", model: "" });
  }

  function setRoute(task: DastModelTask, provider: DastModelProvider, model: string) {
    const base = defaults.get(task);
    if (base && base.provider === provider && base.model === model) {
      const next = { ...value };
      delete next[task];
      onChange(next);
    } else {
      onChange({ ...value, [task]: { provider, model } });
    }
  }

  function setProvider(task: DastModelTask, provider: DastModelProvider) {
    setRoute(task, provider, defaultDastModel(provider, settings, providers, dastOptions(provider)));
  }

  function setAll(provider: DastModelProvider | "") {
    if (!provider) {
      onChange({});
      return;
    }
    const model = defaultDastModel(provider, settings, providers, dastOptions(provider));
    const next: Partial<Record<DastModelTask, DastModelChoice>> = {};
    for (const { task } of TASKS) {
      const base = defaults.get(task);
      if (!base || base.provider !== provider || base.model !== model) {
        next[task] = { provider, model };
      }
    }
    onChange(next);
  }

  const unique = new Set(TASKS.map(({ task }) => currentFor(task).provider));
  const scanProvider = unique.size === 1 ? [...unique][0] : "";
  const topValue = changed === 0 ? "" : unique.size > 1 ? "__mixed" : scanProvider;
  const missingTop = scanProvider && configured.get(scanProvider) === false;
  const uniqueModels = new Set(TASKS.map(({ task }) => currentFor(task).model));
  const scanModelLabel = scanProvider && uniqueModels.size === 1
    ? (DAST_MODEL_OPTIONS[scanProvider] ?? []).find((o) => o.id === [...uniqueModels][0])?.label
    : undefined;

  return (
    <details className="rounded-md border border-slate-200 p-4" open>
      <summary className="cursor-pointer text-sm font-medium text-[var(--ink)]">
        Model for this scan{" "}
        <span className="font-normal text-[var(--muted)]">
          {changed === 0
            ? "(using the configured routing)"
            : scanProvider
              ? `(${PROVIDER_LABELS[scanProvider]}${scanModelLabel ? ` · ${scanModelLabel}` : ""})`
              : `(${changed} task${changed === 1 ? "" : "s"} changed)`}
        </span>
      </summary>
      {!settings ? (
        <p className="mt-3 text-sm text-[var(--muted)]">Loading the configured routing…</p>
      ) : (
        <div className="mt-3 space-y-3">
          <div>
            <label htmlFor="dast-scan-provider" className="block text-sm font-medium text-[var(--ink)]">
              Provider for this scan
            </label>
            <select
              id="dast-scan-provider"
              value={topValue}
              onChange={(e) => {
                const next = e.target.value;
                if (next === "__mixed") return;
                setAll(next as DastModelProvider | "");
              }}
              className={selectClass}
            >
              <option value="">Configured routing</option>
              {topValue === "__mixed" && <option value="__mixed">Mixed (set per task below)</option>}
              {dastProviders(PROVIDERS, scanProvider).map((p) => (
                <option key={p} value={p}>
                  {PROVIDER_LABELS[p]}
                  {p === "bedrock" ? " — Claude Haiku 4.5" : ""}
                </option>
              ))}
            </select>
            {missingTop && (
              <p role="alert" className="mt-1 text-xs text-amber-800">
                No credentials for {PROVIDER_LABELS[scanProvider]} are configured on the server; this scan would fall back
                to the deterministic path.
              </p>
            )}
          </div>
          {!showPerTask && unique.size <= 1 && (
            <button type="button" onClick={() => setShowPerTask(true)} className="text-xs font-medium text-[var(--accent)] hover:underline">
              Customize per task
            </button>
          )}
          {(showPerTask || unique.size > 1) &&
            TASKS.map(({ task, label }) => {
              const current = currentFor(task);
              const missing = configured.get(current.provider) === false;
              return (
                <div key={task} className="grid items-start gap-2 sm:grid-cols-[10rem_1fr_1fr]">
                  <span className="pt-2 text-sm text-[var(--ink)]">{label}</span>
                  <div>
                    <label htmlFor={`model-${task}-provider`} className="sr-only">
                      {label} provider
                    </label>
                    <select
                      id={`model-${task}-provider`}
                      value={current.provider}
                      onChange={(e) => setProvider(task, e.target.value as DastModelProvider)}
                      className={selectClass.replace("mt-1.5", "mt-0")}
                    >
                      {dastProviders(PROVIDERS, current.provider).map((p) => (
                        <option key={p} value={p}>
                          {PROVIDER_LABELS[p]}
                        </option>
                      ))}
                    </select>
                    {missing && (
                      <p role="alert" className="mt-1 text-xs text-amber-800">
                        No credentials for {PROVIDER_LABELS[current.provider]} are configured on the server; this scan would
                        fall back to the deterministic path for this task.
                      </p>
                    )}
                  </div>
                  <ModelSelect
                    id={`model-${task}-model`}
                    provider={current.provider}
                    model={current.model}
                    onChange={(model) => setRoute(task, current.provider, model)}
                  />
                </div>
              );
            })}
          {changed > 0 && (
            <button type="button" onClick={() => onChange({})} className="text-xs font-medium text-[var(--accent)] hover:underline">
              Back to the configured routing
            </button>
          )}
        </div>
      )}
    </details>
  );
}
