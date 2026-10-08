"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { useConfirmDialog } from "@/components/ConfirmDialog";
import { ApiError, api } from "@/lib/api";
import type { DastCustomRule, DastCustomRuleValidation } from "@/lib/types";

const TEMPLATE = `check_id: custom-example
title: Example check
description: What this check looks for.
severity: LOW
mode: assist-only
`;

/** Author, validate, save and delete custom rules in YAML (DAST-15-050). Validation lists every
 *  error with its field; save is only offered once the text validates. */
export default function DastCustomRulesEditor({ onChanged }: { onChanged: () => void }) {
  const [rules, setRules] = useState<DastCustomRule[]>([]);
  const [editing, setEditing] = useState<string | "new" | null>(null);
  const [text, setText] = useState(TEMPLATE);
  const [validation, setValidation] = useState<DastCustomRuleValidation | null>(null);
  const [validatedText, setValidatedText] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { confirm, dialog } = useConfirmDialog();
  const editorRef = useRef<HTMLTextAreaElement>(null);

  const load = useCallback(async () => {
    try {
      setRules(await api.dast.customRules.list());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load custom rules.");
    }
  }, []);
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount
    void load();
  }, [load]);

  function open(id: string | "new", yaml: string) {
    setEditing(id);
    setText(yaml);
    setValidation(null);
    setValidatedText(null);
    setError(null);
    setTimeout(() => editorRef.current?.focus(), 0);
  }

  async function validate() {
    setBusy(true);
    setError(null);
    try {
      setValidation(await api.dast.customRules.validate(text));
      setValidatedText(text);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not validate.");
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      if (editing === "new") await api.dast.customRules.create(text);
      else if (editing) await api.dast.customRules.update(editing, text);
      setEditing(null);
      await load();
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not save.");
    } finally {
      setBusy(false);
    }
  }

  async function remove(rule: DastCustomRule) {
    if (!(await confirm({ title: `Delete ${rule.check_id}?`, message: "Scans will stop running this rule. Findings it already produced are kept.", confirmLabel: "Delete" }))) return;
    try {
      await api.dast.customRules.delete(rule.check_id);
      if (editing === rule.check_id) setEditing(null);
      await load();
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not delete.");
    }
  }

  const stale = validatedText !== text;
  const canSave = !!validation?.valid && !stale && !busy;

  return (
    <div className="space-y-4">
      {dialog}
      {error && <p role="alert" className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}
      {rules.length === 0 ? (
        <p className="text-sm text-[var(--muted)]">No custom rules yet.</p>
      ) : (
        <ul className="divide-y divide-slate-100 rounded-md border border-slate-200">
          {rules.map((rule) => (
            <li key={rule.id} className="flex flex-wrap items-center gap-3 px-3 py-2 text-sm">
              <span className="font-mono text-[var(--ink)]">{rule.check_id}</span>
              <span className="text-xs text-[var(--muted)]">v{rule.version}{rule.enabled ? "" : " · disabled"}</span>
              {rule.notes.map((n) => <span key={n} className="text-xs text-amber-800">{n}</span>)}
              <span className="ml-auto flex gap-2">
                <button type="button" onClick={() => open(rule.check_id, rule.yaml)} className="agent-focus-ring rounded-md border border-slate-300 px-2.5 py-1 text-xs font-medium hover:bg-slate-50">Edit</button>
                <button type="button" onClick={() => remove(rule)} className="agent-focus-ring rounded-md border border-red-200 px-2.5 py-1 text-xs font-medium text-red-700 hover:bg-red-50">Delete</button>
              </span>
            </li>
          ))}
        </ul>
      )}
      {editing === null ? (
        <button type="button" onClick={() => open("new", TEMPLATE)} className="agent-focus-ring rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50">New custom rule</button>
      ) : (
        <div className="space-y-2 rounded-md border border-slate-200 p-3">
          <label htmlFor="custom-rule-yaml" className="text-sm font-medium text-[var(--ink)]">{editing === "new" ? "New rule (YAML)" : `Editing ${editing}`}</label>
          <textarea id="custom-rule-yaml" ref={editorRef} value={text} onChange={(e) => setText(e.target.value)} rows={14} spellCheck={false} aria-describedby="custom-rule-result" className="agent-focus-ring w-full rounded-md border border-slate-300 px-3 py-2 font-mono text-xs text-[var(--ink)]" />
          <div id="custom-rule-result" aria-live="polite">
            {validation && !stale && (validation.valid ? (
              <p className="text-sm text-emerald-700">The rule is valid.</p>
            ) : (
              <ul className="space-y-1 text-sm text-red-700">
                {validation.errors.map((e, i) => <li key={i}><span className="font-mono">{e.field || "rule"}</span>: {e.message}</li>)}
              </ul>
            ))}
            {validation && !stale && validation.notes.map((n) => <p key={n} className="text-xs text-amber-800">{n}</p>)}
            {validation && stale && <p className="text-xs text-[var(--muted)]">Edited since the last check. Validate again before saving.</p>}
          </div>
          <div className="flex gap-2">
            <button type="button" onClick={validate} disabled={busy} className="agent-focus-ring rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-50 disabled:opacity-50">Validate</button>
            <button type="button" onClick={save} disabled={!canSave} className="agent-focus-ring rounded-md bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50">Save rule</button>
            <button type="button" onClick={() => setEditing(null)} className="agent-focus-ring rounded-md px-3 py-1.5 text-sm text-[var(--muted)] hover:bg-slate-100">Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
}
