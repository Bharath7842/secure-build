"use client";

import { useId, useState } from "react";

import DastAuthzPreview, { RoleBadge } from "@/components/DastAuthzPreview";
import { inputClass, selectClass } from "@/lib/formStyles";
import type { DastAuthMethod, DastIdentityInput, DastRoleName } from "@/lib/types";

/** One identity as the form holds it. Secrets live here, in component state, only until the scan is
 *  submitted: they are never pre-filled, never written to browser storage and never read back. */
export interface IdentityDraft {
  key: string;
  label: string;
  role: Exclude<DastRoleName, "anonymous">;
  customRole: string;
  method: Exclude<DastAuthMethod, "none">;
  loginUrl: string;
  username: string;
  password: string;
  headerName: string;
  scheme: string;
  token: string;
  storageState: string;
  storageFileName: string;
}

export const ROLE_OPTIONS: { value: Exclude<DastRoleName, "anonymous">; label: string }[] = [
  { value: "admin", label: "Admin" },
  { value: "user", label: "User" },
  { value: "viewer", label: "Viewer" },
  { value: "custom", label: "Custom" },
];

const METHODS: { value: IdentityDraft["method"]; label: string }[] = [
  { value: "form", label: "Form login" },
  { value: "token", label: "Token" },
  { value: "preauth", label: "Saved session" },
];

let counter = 0;

export function newIdentity(partial: Partial<IdentityDraft> = {}): IdentityDraft {
  counter += 1;
  return {
    key: `identity-${counter}`,
    label: "",
    role: "user",
    customRole: "",
    method: "form",
    loginUrl: "",
    username: "",
    password: "",
    headerName: "Authorization",
    scheme: "Bearer",
    token: "",
    storageState: "",
    storageFileName: "",
    ...partial,
  };
}

/** Problems with one identity, as messages tied to its fields (empty when it is complete). */
export function identityProblems(draft: IdentityDraft, all: IdentityDraft[]): Record<string, string> {
  const problems: Record<string, string> = {};
  const label = draft.label.trim();
  if (!label) problems.label = "Give this identity a label.";
  else if (all.some((other) => other !== draft && other.label.trim().toLowerCase() === label.toLowerCase()))
    problems.label = "Another identity already uses this label.";
  if (draft.role === "custom" && !draft.customRole.trim()) problems.customRole = "Name the custom role.";
  if (draft.method === "form") {
    if (!draft.loginUrl.trim()) problems.loginUrl = "Enter the login page URL.";
    if (!draft.username.trim()) problems.username = "Enter the username.";
    if (!draft.password) problems.password = "Enter the password.";
  } else if (draft.method === "token") {
    if (!draft.token.trim()) problems.token = "Enter the token.";
    if (!draft.headerName.trim()) problems.headerName = "Name the header the token is sent in.";
  } else if (!draft.storageState) {
    problems.storageState = "Choose the saved session file (Playwright storage-state JSON).";
  }
  return problems;
}

/** The identity as the API wants it. Call only when `identityProblems` is empty. */
export function toIdentityInput(draft: IdentityDraft): DastIdentityInput {
  const base: DastIdentityInput = {
    label: draft.label.trim(),
    role: ROLE_OPTIONS.find((r) => r.value === draft.role)!.label,
    custom_role: draft.role === "custom" ? draft.customRole.trim() : undefined,
    auth_method: draft.method,
  };
  if (draft.method === "form") return { ...base, login_url: draft.loginUrl.trim(), username: draft.username.trim(), password: draft.password };
  if (draft.method === "token") return { ...base, token: draft.token.trim(), header_name: draft.headerName.trim(), scheme: draft.scheme };
  return { ...base, storage_state: draft.storageState };
}

function Field({ id, label, error, children }: { id: string; label: string; error?: string; children: React.ReactNode }) {
  return (
    <div>
      <label htmlFor={id} className="block text-sm text-[var(--ink)]">
        {label}
      </label>
      {children}
      {error && (
        <p id={`${id}-error`} role="alert" className="mt-1 text-xs text-red-700">
          {error}
        </p>
      )}
    </div>
  );
}

function IdentityCard({
  draft,
  all,
  showErrors,
  onChange,
  onRemove,
}: {
  draft: IdentityDraft;
  all: IdentityDraft[];
  showErrors: boolean;
  onChange: (next: IdentityDraft) => void;
  onRemove: () => void;
}) {
  const uid = useId();
  const problems = identityProblems(draft, all);
  const err = (name: string) => (showErrors || (name === "label" && draft.label) ? problems[name] : undefined);
  const set = <K extends keyof IdentityDraft>(key: K, value: IdentityDraft[K]) => onChange({ ...draft, [key]: value });

  function readFile(file: File | undefined) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => onChange({ ...draft, storageState: String(reader.result ?? ""), storageFileName: file.name });
    reader.readAsText(file);
  }

  return (
    <div className="space-y-3 rounded-md border border-slate-200 bg-white p-4" role="group" aria-label={`Identity ${draft.label || "(unnamed)"}`}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <RoleBadge role={draft.role} customName={draft.customRole} />
          <span className="text-sm font-medium text-[var(--ink)]">{draft.label.trim() || "New identity"}</span>
        </div>
        <button
          type="button"
          onClick={onRemove}
          className="agent-focus-ring rounded-md px-2 py-1 text-xs font-medium text-red-600 hover:bg-red-50"
          aria-label={`Remove identity ${draft.label || "(unnamed)"}`}
        >
          Remove
        </button>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <Field id={`${uid}-label`} label="Label" error={err("label")}>
          <input
            id={`${uid}-label`}
            value={draft.label}
            onChange={(e) => set("label", e.target.value)}
            className={inputClass}
            placeholder="e.g. alice"
            aria-invalid={Boolean(err("label"))}
            aria-describedby={err("label") ? `${uid}-label-error` : undefined}
            autoComplete="off"
          />
        </Field>
        <Field id={`${uid}-role`} label="Role">
          <select id={`${uid}-role`} value={draft.role} onChange={(e) => set("role", e.target.value as IdentityDraft["role"])} className={selectClass}>
            {ROLE_OPTIONS.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </Field>
        {draft.role === "custom" && (
          <Field id={`${uid}-custom`} label="Role name" error={err("customRole")}>
            <input
              id={`${uid}-custom`}
              value={draft.customRole}
              onChange={(e) => set("customRole", e.target.value)}
              className={inputClass}
              placeholder="e.g. Auditor"
              aria-invalid={Boolean(err("customRole"))}
              aria-describedby={err("customRole") ? `${uid}-custom-error` : undefined}
            />
          </Field>
        )}
      </div>

      <fieldset>
        <legend className="text-sm text-[var(--ink)]">How it signs in</legend>
        <div className="mt-1.5 inline-flex rounded-md border border-slate-200 p-0.5" role="radiogroup" aria-label="Authentication method">
          {METHODS.map((m) => (
            <label
              key={m.value}
              className={`cursor-pointer rounded px-3 py-1 text-sm font-medium transition-colors focus-within:ring-2 focus-within:ring-[var(--accent)]/40 ${
                draft.method === m.value ? "bg-[var(--accent)] text-white" : "text-[var(--ink)] hover:bg-slate-50"
              }`}
            >
              <input
                type="radio"
                name={`${uid}-method`}
                value={m.value}
                checked={draft.method === m.value}
                onChange={() => set("method", m.value)}
                className="sr-only"
              />
              {m.label}
            </label>
          ))}
        </div>
      </fieldset>

      {draft.method === "form" && (
        <div className="grid gap-3 sm:grid-cols-3">
          <Field id={`${uid}-login`} label="Login page URL" error={err("loginUrl")}>
            <input id={`${uid}-login`} type="url" value={draft.loginUrl} onChange={(e) => set("loginUrl", e.target.value)} className={inputClass} placeholder="http://localhost:3000/login" aria-invalid={Boolean(err("loginUrl"))} aria-describedby={err("loginUrl") ? `${uid}-login-error` : undefined} />
          </Field>
          <Field id={`${uid}-user`} label="Username" error={err("username")}>
            <input id={`${uid}-user`} value={draft.username} onChange={(e) => set("username", e.target.value)} className={inputClass} autoComplete="off" aria-invalid={Boolean(err("username"))} aria-describedby={err("username") ? `${uid}-user-error` : undefined} />
          </Field>
          <Field id={`${uid}-pass`} label="Password" error={err("password")}>
            <input id={`${uid}-pass`} type="password" value={draft.password} onChange={(e) => set("password", e.target.value)} className={inputClass} autoComplete="new-password" aria-invalid={Boolean(err("password"))} aria-describedby={err("password") ? `${uid}-pass-error` : undefined} />
          </Field>
        </div>
      )}
      {draft.method === "token" && (
        <div className="grid gap-3 sm:grid-cols-3">
          <Field id={`${uid}-header`} label="Header name" error={err("headerName")}>
            <input id={`${uid}-header`} value={draft.headerName} onChange={(e) => set("headerName", e.target.value)} className={inputClass} aria-invalid={Boolean(err("headerName"))} aria-describedby={err("headerName") ? `${uid}-header-error` : undefined} />
          </Field>
          <Field id={`${uid}-scheme`} label="Scheme">
            <input id={`${uid}-scheme`} value={draft.scheme} onChange={(e) => set("scheme", e.target.value)} className={inputClass} placeholder="Bearer (blank = token only)" />
          </Field>
          <Field id={`${uid}-token`} label="Token" error={err("token")}>
            <input id={`${uid}-token`} type="password" value={draft.token} onChange={(e) => set("token", e.target.value)} className={inputClass} autoComplete="new-password" aria-invalid={Boolean(err("token"))} aria-describedby={err("token") ? `${uid}-token-error` : undefined} />
          </Field>
        </div>
      )}
      {draft.method === "preauth" && (
        <Field id={`${uid}-state`} label="Saved session file" error={err("storageState")}>
          <input
            id={`${uid}-state`}
            type="file"
            accept="application/json,.json"
            onChange={(e) => readFile(e.target.files?.[0])}
            className="mt-1.5 block w-full text-sm text-[var(--ink)] file:mr-3 file:rounded-md file:border file:border-slate-300 file:bg-white file:px-3 file:py-1.5 file:text-sm file:font-medium"
            aria-invalid={Boolean(err("storageState"))}
            aria-describedby={err("storageState") ? `${uid}-state-error` : undefined}
          />
          <p className="mt-1 text-xs text-[var(--muted)]">
            {draft.storageFileName ? `Loaded ${draft.storageFileName}. ` : ""}A Playwright storage-state JSON file. It is
            read in your browser and sent with the scan request; it is not stored.
          </p>
        </Field>
      )}
    </div>
  );
}

interface DastIdentitiesEditorProps {
  identities: IdentityDraft[];
  onChange: (next: IdentityDraft[]) => void;
  showErrors: boolean;
}

/** The identity list (DAST-13-030): one card per identity, Anonymous shown as implied, with a live
 *  preview of which role pairs the authorization checks will test. */
export default function DastIdentitiesEditor({ identities, onChange, showErrors }: DastIdentitiesEditorProps) {
  const [addedOnce, setAddedOnce] = useState(false);
  return (
    <fieldset className="space-y-4 rounded-md border border-slate-200 p-4">
      <legend className="px-1 text-sm font-medium text-[var(--ink)]">
        Identities <span className="font-normal text-[var(--muted)]">(optional)</span>
      </legend>
      <p className="text-xs text-[var(--muted)]">
        Add the accounts the scan should act as. With two or more, every identity&apos;s requests are replayed as every
        other, which finds broken access control. Credentials are held in memory for this run only: they are never stored,
        logged or shown again.
      </p>

      {identities.map((draft) => (
        <IdentityCard
          key={draft.key}
          draft={draft}
          all={identities}
          showErrors={showErrors}
          onChange={(next) => onChange(identities.map((d) => (d.key === draft.key ? next : d)))}
          onRemove={() => onChange(identities.filter((d) => d.key !== draft.key))}
        />
      ))}

      <div className="flex items-center gap-3 rounded-md border border-dashed border-slate-300 bg-slate-50/60 px-4 py-3" aria-label="Anonymous identity (implied)">
        <RoleBadge role="anonymous" />
        <p className="text-sm text-[var(--muted)]">
          <span className="font-medium text-[var(--ink)]">Anonymous</span> is always tested as the no-session baseline. It
          is implied and cannot be removed.
        </p>
      </div>

      <button
        type="button"
        onClick={() => {
          setAddedOnce(true);
          onChange([...identities, newIdentity({ role: identities.length === 0 ? "admin" : "user" })]);
        }}
        className="agent-focus-ring rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-[var(--ink)] hover:bg-slate-50"
      >
        + Add identity
      </button>
      {identities.length === 0 && addedOnce && <p className="text-xs text-[var(--muted)]">All identities removed: the scan will run anonymously.</p>}

      <DastAuthzPreview identities={identities.map((i) => ({ label: i.label, role: i.role, customName: i.customRole }))} />
    </fieldset>
  );
}
