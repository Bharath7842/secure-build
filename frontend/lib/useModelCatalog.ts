"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "@/lib/api";
import { DAST_MODEL_OPTIONS } from "@/lib/dastModels";
import { LLM_PRESETS, type LlmPresetId, type LlmPresetInfo } from "@/lib/llmPresets";
import type { ModelCatalog } from "@/lib/types";

/** Everything visible, from the bundled lists — used until the backend answers, and if it never does. */
function bundledCatalog(): ModelCatalog {
  return {
    sast: Object.entries(LLM_PRESETS).map(([id, p]) => ({
      key: `sast:${id}`,
      id,
      label: p.label,
      provider: p.provider,
      model: p.model,
      visible: true,
      pinned: id === "ollama-granite-3b-instruct",
    })),
    dast: Object.fromEntries(
      Object.entries(DAST_MODEL_OPTIONS).map(([provider, options]) => [
        provider,
        options.map((o) => ({
          key: `dast:${provider}:${o.id}`,
          id: o.id,
          label: o.label,
          provider,
          model: o.id,
          visible: true,
          pinned: provider === "ollama" && o.id === "granite-code:3b-instruct",
        })),
      ]),
    ),
    hidden: [],
  };
}

let cached: ModelCatalog | null = null;
let inflight: Promise<ModelCatalog | null> | null = null;
const listeners = new Set<(catalog: ModelCatalog) => void>();

function load(): Promise<ModelCatalog | null> {
  if (cached) return Promise.resolve(cached);
  inflight ??= api.settings.models
    .get()
    .then((catalog) => {
      cached = catalog;
      return catalog;
    })
    .catch(() => null)
    .finally(() => {
      inflight = null;
    });
  return inflight;
}

/** Call after saving Settings so open forms and the next page see the new visibility. */
export function setModelCatalog(catalog: ModelCatalog) {
  cached = catalog;
  listeners.forEach((fn) => fn(catalog));
}

export interface ModelOption {
  id: string;
  label: string;
}

/**
 * The model catalog with Settings visibility applied. Falls back to the bundled lists (all visible)
 * if the backend can't be reached, so a form never ends up without options. A model that is hidden
 * but currently selected stays in its dropdown, so editing an existing project never loses its value.
 */
export function useModelCatalog() {
  const [catalog, setCatalog] = useState<ModelCatalog>(() => cached ?? bundledCatalog());

  useEffect(() => {
    let active = true;
    const listener = (next: ModelCatalog) => active && setCatalog(next);
    listeners.add(listener);
    void load().then((next) => {
      if (active && next) setCatalog(next);
    });
    return () => {
      active = false;
      listeners.delete(listener);
    };
  }, []);

  /** Every SAST preset, hidden ones included: for resolving stored settings and selected ids. */
  const presets = useMemo(() => {
    const merged: Record<LlmPresetId, LlmPresetInfo> = { ...LLM_PRESETS };
    for (const m of catalog.sast) {
      merged[m.id] = { label: m.label, provider: m.provider as LlmPresetInfo["provider"], model: m.model };
    }
    return merged;
  }, [catalog]);

  const sastOptions = useCallback(
    (currentId?: LlmPresetId): [LlmPresetId, LlmPresetInfo][] =>
      catalog.sast
        .filter((m) => m.visible || m.id === currentId)
        .map((m) => [m.id, { ...presets[m.id], label: m.visible ? m.label : `${m.label} (hidden)` }]),
    [catalog, presets],
  );

  const dastOptions = useCallback(
    (provider: string, currentModel?: string): ModelOption[] =>
      (catalog.dast[provider] ?? [])
        .filter((m) => m.visible || m.id === currentModel)
        .map((m) => ({ id: m.id, label: m.visible ? m.label : `${m.label} (hidden)` })),
    [catalog],
  );

  /** Providers that still offer a model, plus `currentProvider` so a saved choice never vanishes. */
  const dastProviders = useCallback(
    <P extends string>(all: P[], currentProvider?: string): P[] =>
      all.filter((p) => p === currentProvider || (catalog.dast[p] ?? []).some((m) => m.visible)),
    [catalog],
  );

  return { catalog, presets, sastOptions, dastOptions, dastProviders };
}
