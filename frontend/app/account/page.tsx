"use client";

import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";

import { useAuth } from "@/components/auth/AuthProvider";
import { MIN_PASSWORD_LENGTH, newPasswordProblem } from "@/components/auth/NewPasswordFields";
import PageContainer from "@/components/PageContainer";
import type { SessionInfo } from "@/lib/access";
import { ApiError, api } from "@/lib/api";
import { inputClass } from "@/lib/formStyles";

function formatWhen(value: string): string {
  return new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** A short device description from a user-agent string. */
function deviceLabel(ua: string | null): string {
  if (!ua) return "Unknown device";
  const browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}

function ChangePassword() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setNotice(null);
    const problem = current ? newPasswordProblem(next, confirm) : "Enter your current password.";
    setError(problem);
    if (problem) return;
    setBusy(true);
    try {
      await api.account.changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setNotice("Password changed. You've been signed out on your other devices.");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not change the password.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="mt-10 max-w-md" aria-labelledby="pw-title">
      <h2 id="pw-title" className="font-display text-xl text-[var(--ink)]">
        Change password
      </h2>
      <form onSubmit={submit} noValidate className="mt-4 space-y-4">
        <label className="block text-sm">
          <span className="font-medium text-[var(--ink)]">Current password</span>
          <input
            type="password"
            autoComplete="current-password"
            className={inputClass}
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
        </label>
        <label className="block text-sm">
          <span className="font-medium text-[var(--ink)]">New password</span>
          <input
            type="password"
            autoComplete="new-password"
            className={inputClass}
            value={next}
            onChange={(e) => setNext(e.target.value)}
            aria-describedby="pw-help"
          />
          <span id="pw-help" className="mt-1 block text-xs text-[var(--muted)]">
            At least {MIN_PASSWORD_LENGTH} characters.
          </span>
        </label>
        <label className="block text-sm">
          <span className="font-medium text-[var(--ink)]">Confirm new password</span>
          <input
            type="password"
            autoComplete="new-password"
            className={inputClass}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </label>
        {error && (
          <p role="alert" className="text-sm text-red-700">
            {error}
          </p>
        )}
        {notice && (
          <p role="status" className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800">
            {notice}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-60"
        >
          {busy ? "Saving…" : "Change password"}
        </button>
      </form>
    </section>
  );
}

function Sessions() {
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.account
      .sessions()
      .then(setSessions)
      .catch((err) => setError(err instanceof ApiError ? err.message : "Could not load your sessions."));
  }, []);

  useEffect(load, [load]);

  async function signOutOthers() {
    setBusy(true);
    try {
      await api.account.revokeOtherSessions();
      load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not sign out the other sessions.");
    } finally {
      setBusy(false);
    }
  }

  const others = (sessions ?? []).filter((s) => !s.current).length;
  return (
    <section className="mt-12 max-w-2xl" aria-labelledby="sessions-title">
      <div className="flex items-baseline justify-between gap-4">
        <h2 id="sessions-title" className="font-display text-xl text-[var(--ink)]">
          Where you&apos;re signed in
        </h2>
        {others > 0 && (
          <button
            type="button"
            onClick={signOutOthers}
            disabled={busy}
            className="text-sm font-medium text-red-600 hover:text-red-700 disabled:opacity-60"
          >
            {busy ? "Signing out…" : `Sign out ${others} other session${others === 1 ? "" : "s"}`}
          </button>
        )}
      </div>
      {error && (
        <p role="alert" className="mt-3 text-sm text-red-700">
          {error}
        </p>
      )}
      {sessions === null && !error ? (
        <p className="mt-4 text-sm text-[var(--muted)]">Loading…</p>
      ) : (
        <ul className="mt-4 divide-y divide-slate-100 rounded-lg border border-slate-200 bg-white">
          {(sessions ?? []).map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-4 px-4 py-3 text-sm">
              <div>
                <p className="font-medium text-[var(--ink)]">
                  {deviceLabel(s.user_agent)}
                  {s.current && (
                    <span className="ml-2 rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700">
                      This device
                    </span>
                  )}
                </p>
                <p className="text-xs text-[var(--muted)]">
                  {s.ip ? `${s.ip} · ` : ""}Last active {formatWhen(s.last_seen_at)}
                </p>
              </div>
              <span className="text-xs text-[var(--muted)]">Signed in {formatWhen(s.created_at)}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default function AccountPage() {
  const me = useAuth();
  if (!me) return null;
  return (
    <PageContainer>
      <h1 className="font-display text-3xl text-[var(--ink)]">Your account</h1>
      <dl className="mt-6 grid max-w-md grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
        <dt className="text-[var(--muted)]">Name</dt>
        <dd className="text-[var(--ink)]">{me.user.display_name || "—"}</dd>
        <dt className="text-[var(--muted)]">Email</dt>
        <dd className="text-[var(--ink)]">{me.user.email}</dd>
        <dt className="text-[var(--muted)]">Role</dt>
        <dd className="text-[var(--ink)]">{me.user.role === "admin" ? "Admin" : "User"}</dd>
      </dl>
      <p className="mt-3 max-w-md text-xs text-[var(--muted)]">To change your name, email or access, ask an administrator.</p>
      <ChangePassword />
      <Sessions />
    </PageContainer>
  );
}
