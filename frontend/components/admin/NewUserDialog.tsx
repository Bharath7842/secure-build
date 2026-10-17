"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import type { FormEvent } from "react";

import OneTimeLinkPanel from "@/components/admin/OneTimeLinkPanel";
import type { AppRole, AppUser } from "@/lib/access";
import { ApiError, api } from "@/lib/api";
import { inputClass } from "@/lib/formStyles";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Create a user by invite: they get no password until they open the link. */
export default function NewUserDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (user: AppUser) => void }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<AppRole>("user");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ user: AppUser; url: string; expires: string } | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!EMAIL_RE.test(email.trim())) {
      setError("Enter a valid email address, like name@company.com.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const out = await api.admin.createUser({ email: email.trim(), display_name: name.trim(), role });
      setCreated({ user: out.user, url: out.invite_url, expires: out.invite_expires_at });
      onCreated(out.user);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create the user.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="new-user-title"
        className="w-full max-w-lg rounded-lg bg-white p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="new-user-title" className="font-display text-xl text-[var(--ink)]">
          {created ? `Invite ${created.user.email}` : "New user"}
        </h2>

        {created ? (
          <>
            <div className="mt-4">
              <OneTimeLinkPanel url={created.url} expiresAt={created.expires} kind="invite" />
            </div>
            <p className="mt-4 text-sm text-[var(--muted)]">
              {created.user.role === "admin"
                ? "Admins have full access."
                : "They start with the default access for users. You can change what they can see and do at any time."}
            </p>
            <div className="mt-6 flex justify-end gap-3">
              {created.user.role === "user" && (
                <Link
                  href={`/admin/users/${created.user.id}`}
                  className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50"
                >
                  Set access
                </Link>
              )}
              <button
                type="button"
                onClick={onClose}
                className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
              >
                Done
              </button>
            </div>
          </>
        ) : (
          <form onSubmit={submit} noValidate className="mt-4 space-y-4">
            <label className="block text-sm">
              <span className="font-medium text-[var(--ink)]">Email</span>
              <input
                autoFocus
                type="email"
                autoComplete="off"
                className={inputClass}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@company.com"
              />
            </label>
            <label className="block text-sm">
              <span className="font-medium text-[var(--ink)]">
                Name <span className="font-normal text-[var(--muted)]">(optional)</span>
              </span>
              <input className={inputClass} maxLength={120} value={name} onChange={(e) => setName(e.target.value)} />
            </label>
            <fieldset className="text-sm">
              <legend className="font-medium text-[var(--ink)]">Role</legend>
              <div className="mt-2 space-y-2">
                {(
                  [
                    ["user", "User", "Sees only the pages and actions you allow."],
                    ["admin", "Admin", "Full access, including users, settings and the audit log."],
                  ] as const
                ).map(([value, label, help]) => (
                  <label key={value} className="flex cursor-pointer items-start gap-3 rounded-md border border-slate-200 p-3 has-[:checked]:border-[var(--accent)]">
                    <input
                      type="radio"
                      name="role"
                      value={value}
                      checked={role === value}
                      onChange={() => setRole(value)}
                      className="mt-0.5 accent-[var(--accent)]"
                    />
                    <span>
                      <span className="font-medium text-[var(--ink)]">{label}</span>
                      <span className="block text-xs text-[var(--muted)]">{help}</span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
            {error && (
              <p role="alert" className="text-sm text-red-700">
                {error}
              </p>
            )}
            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={busy}
                className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-60"
              >
                {busy ? "Creating…" : "Create and get invite link"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
