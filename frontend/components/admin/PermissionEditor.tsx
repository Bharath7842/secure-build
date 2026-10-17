"use client";

import type { Override, PermissionEntry, UserAccess } from "@/lib/access";

type Choice = "default" | Override;

const CHOICES: { value: Choice; label: string }[] = [
  { value: "default", label: "Default" },
  { value: "grant", label: "Allow" },
  { value: "deny", label: "Deny" },
];

function Row({
  entry,
  choice,
  effective,
  missing,
  labelOf,
  onChange,
  disabled,
}: {
  entry: PermissionEntry;
  choice: Choice;
  effective: boolean;
  missing: string[] | undefined;
  labelOf: (key: string) => string;
  onChange: (choice: Choice) => void;
  disabled: boolean;
}) {
  const name = `perm-${entry.key}`;
  return (
    <li className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <p className="text-sm font-medium text-[var(--ink)]">
          {entry.label}
          <span className="ml-2 text-xs font-normal text-[var(--muted)]">
            {entry.grantable_to_user ? (entry.user_default ? "on by default" : "off by default") : "admins only"}
          </span>
        </p>
        <p className="text-xs text-[var(--muted)]">{entry.description}</p>
        {missing && missing.length > 0 && (
          <p className="mt-1 text-xs text-amber-700">Not active: needs {missing.map(labelOf).join(", ")}.</p>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <fieldset disabled={disabled || !entry.grantable_to_user} className="flex rounded-md border border-slate-200 bg-white p-0.5">
          <legend className="sr-only">{entry.label}</legend>
          {CHOICES.map((c) => (
            <label
              key={c.value}
              className={`cursor-pointer rounded px-2.5 py-1 text-xs font-medium transition-colors has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-[var(--accent)] ${
                choice === c.value
                  ? c.value === "deny"
                    ? "bg-red-50 text-red-700"
                    : c.value === "grant"
                      ? "bg-emerald-50 text-emerald-700"
                      : "bg-slate-100 text-[var(--ink)]"
                  : "text-[var(--muted)] hover:text-[var(--ink)]"
              } ${disabled || !entry.grantable_to_user ? "cursor-not-allowed opacity-50" : ""}`}
            >
              <input
                type="radio"
                name={name}
                value={c.value}
                checked={choice === c.value}
                onChange={() => onChange(c.value)}
                className="sr-only"
              />
              {c.label}
            </label>
          ))}
        </fieldset>
        <span
          className={`w-16 rounded-full px-2 py-0.5 text-center text-xs font-medium ${
            effective ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-500"
          }`}
        >
          {effective ? "Has it" : "No"}
        </span>
      </div>
    </li>
  );
}

/**
 * Pages and actions for one regular user. Each row overrides the role
 * default (Allow / Deny) or keeps it; "Has it" shows the saved result,
 * including requirements (a page needs the action behind it).
 */
export default function PermissionEditor({
  catalog,
  overrides,
  saved,
  onChange,
  disabled = false,
}: {
  catalog: PermissionEntry[];
  overrides: Record<string, Override>;
  /** The access as last saved, from the server. */
  saved: UserAccess;
  onChange: (overrides: Record<string, Override>) => void;
  disabled?: boolean;
}) {
  const effective = new Set(saved.effective);
  const missing = new Map(saved.inactive.map((i) => [i.key, i.missing]));
  const labels = new Map(catalog.map((e) => [e.key, e.label]));
  const labelOf = (key: string) => labels.get(key) ?? key;

  function set(key: string, choice: Choice) {
    const next = { ...overrides };
    if (choice === "default") delete next[key];
    else next[key] = choice;
    onChange(next);
  }

  return (
    <div className="grid gap-8 lg:grid-cols-2">
      {(["page", "action"] as const).map((kind) => (
        <section key={kind} aria-labelledby={`perm-group-${kind}`}>
          <h3 id={`perm-group-${kind}`} className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
            {kind === "page" ? "Pages they can open" : "What they can do"}
          </h3>
          <ul className="mt-2 divide-y divide-slate-100">
            {catalog
              .filter((e) => e.kind === kind)
              .map((entry) => (
                <Row
                  key={entry.key}
                  entry={entry}
                  choice={overrides[entry.key] ?? "default"}
                  effective={effective.has(entry.key)}
                  missing={missing.get(entry.key)}
                  labelOf={labelOf}
                  onChange={(choice) => set(entry.key, choice)}
                  disabled={disabled}
                />
              ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
