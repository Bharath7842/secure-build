"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import OneTimeLinkPanel from "@/components/admin/OneTimeLinkPanel";
import PermissionEditor from "@/components/admin/PermissionEditor";
import { RoleBadge, StatusBadge, formatWhen } from "@/components/admin/badges";
import { useAuth } from "@/components/auth/AuthProvider";
import { useConfirmDialog } from "@/components/ConfirmDialog";
import PageContainer from "@/components/PageContainer";
import type { AppRole, Override, PermissionEntry, UserDetail } from "@/lib/access";
import { ApiError, api } from "@/lib/api";
import { inputClass } from "@/lib/formStyles";

const SECTION = "mt-10 border-t border-slate-200 pt-8";
const BUTTON = "rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50 disabled:opacity-60";
const PRIMARY = "rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-60";

function message(err: unknown, fallback: string): string {
  return err instanceof ApiError ? err.message : fallback;
}

function sameOverrides(a: Record<string, Override>, b: Record<string, Override>): boolean {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...keys].every((k) => a[k] === b[k]);
}

export default function AdminUserPage() {
  const { id } = useParams<{ id: string }>();
  const me = useAuth();
  const { confirm, dialog } = useConfirmDialog();
  const [detail, setDetail] = useState<UserDetail | null>(null);
  const [catalog, setCatalog] = useState<PermissionEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [draft, setDraft] = useState<Record<string, Override>>({});
  const [link, setLink] = useState<{ url: string; expires: string; kind: "invite" | "reset" } | null>(null);

  const load = useCallback(async () => {
    try {
      const [d, c] = await Promise.all([api.admin.user(id), api.admin.catalog()]);
      setDetail(d);
      setCatalog(c.permissions);
      setName(d.user.display_name);
      setDraft(d.overrides);
    } catch (err) {
      setError(message(err, "Could not load this user."));
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  async function run(action: () => Promise<unknown>, done: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await action();
      setNotice(done);
      await load();
    } catch (err) {
      setError(message(err, "That didn't work. Try again."));
    } finally {
      setBusy(false);
    }
  }

  if (!detail) {
    return (
      <PageContainer>
        {error ? (
          <div role="alert" className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        ) : (
          <p className="text-sm text-[var(--muted)]">Loading…</p>
        )}
      </PageContainer>
    );
  }

  const { user } = detail;
  const isSelf = me?.user.id === user.id;
  const dirty = !sameOverrides(draft, detail.overrides);

  async function changeRole(role: AppRole) {
    const toAdmin = role === "admin";
    const ok = await confirm({
      title: toAdmin ? "Make this user an admin?" : "Remove admin access?",
      message: toAdmin
        ? `${user.email} will get full access, including users, settings and the audit log.`
        : `${user.email} will become a regular user with default access and be signed out.`,
      confirmLabel: toAdmin ? "Make admin" : "Remove admin",
      danger: !toAdmin,
    });
    if (ok) await run(() => api.admin.updateUser(user.id, { role }), "Role updated.");
  }

  async function setActive(active: boolean) {
    if (!active) {
      const ok = await confirm({
        title: "Disable this account?",
        message: `${user.email} will be signed out everywhere and can't sign in until you enable the account again. Their scans and reviews are kept.`,
        confirmLabel: "Disable",
      });
      if (!ok) return;
    }
    await run(() => api.admin.updateUser(user.id, { is_active: active }), active ? "Account enabled." : "Account disabled.");
  }

  async function newLink(kind: "invite" | "reset") {
    if (kind === "reset") {
      const ok = await confirm({
        title: "Create a password reset link?",
        message: "Their current password keeps working until they use the link. Using it signs them out everywhere.",
        confirmLabel: "Create link",
        danger: false,
      });
      if (!ok) return;
    }
    setBusy(true);
    setError(null);
    try {
      const out = kind === "invite" ? await api.admin.inviteLink(user.id) : await api.admin.resetLink(user.id);
      setLink({ url: out.url, expires: out.expires_at, kind });
    } catch (err) {
      setError(message(err, "Could not create the link."));
    } finally {
      setBusy(false);
    }
  }

  async function savePermissions() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const out = await api.admin.setPermissions(user.id, draft);
      const added = out.added_dependencies.map((k) => catalog.find((e) => e.key === k)?.label ?? k);
      setNotice(added.length ? `Access saved. Also allowed, because they're needed: ${added.join(", ")}.` : "Access saved.");
      await load();
    } catch (err) {
      setError(message(err, "Could not save access."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <PageContainer>
      {dialog}
      <Link href="/admin/users" className="text-sm font-medium text-[var(--accent)]">
        ← All users
      </Link>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <h1 className="font-display text-3xl text-[var(--ink)]">{user.display_name || user.email}</h1>
        <RoleBadge role={user.role} />
        <StatusBadge status={user.status} />
      </div>
      <p className="mt-1 text-sm text-[var(--muted)]">
        {user.email} · last sign-in {formatWhen(user.last_login_at)} · created {formatWhen(user.created_at)}
      </p>

      <div aria-live="polite" className="mt-6 space-y-3">
        {error && (
          <div role="alert" className="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}
        {notice && (
          <div role="status" className="rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800">
            {notice}
          </div>
        )}
      </div>

      <section className={SECTION} aria-labelledby="profile-title">
        <h2 id="profile-title" className="font-display text-xl text-[var(--ink)]">
          Profile
        </h2>
        <form
          className="mt-4 flex max-w-md items-end gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            void run(() => api.admin.updateUser(user.id, { display_name: name }), "Name updated.");
          }}
        >
          <label className="block flex-1 text-sm">
            <span className="text-[var(--muted)]">Name</span>
            <input className={inputClass} maxLength={120} value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <button type="submit" className={BUTTON} disabled={busy || name.trim() === user.display_name}>
            Save
          </button>
        </form>
      </section>

      <section className={SECTION} aria-labelledby="account-title">
        <h2 id="account-title" className="font-display text-xl text-[var(--ink)]">
          Role and sign-in
        </h2>
        {isSelf && <p className="mt-2 text-sm text-[var(--muted)]">You can&apos;t change your own role or disable your own account.</p>}
        <div className="mt-4 flex flex-wrap gap-3">
          {user.role === "user" ? (
            <button type="button" className={BUTTON} disabled={busy || isSelf} onClick={() => changeRole("admin")}>
              Make admin
            </button>
          ) : (
            <button type="button" className={BUTTON} disabled={busy || isSelf} onClick={() => changeRole("user")}>
              Remove admin
            </button>
          )}
          {user.status === "disabled" ? (
            <button type="button" className={BUTTON} disabled={busy} onClick={() => setActive(true)}>
              Enable account
            </button>
          ) : (
            <button
              type="button"
              className="rounded-md border border-red-200 bg-red-50 px-4 py-2 text-sm font-medium text-red-700 transition-colors hover:bg-red-100 disabled:opacity-60"
              disabled={busy || isSelf}
              onClick={() => setActive(false)}
            >
              Disable account
            </button>
          )}
          {user.status === "invited" && (
            <button type="button" className={BUTTON} disabled={busy} onClick={() => newLink("invite")}>
              New invite link
            </button>
          )}
          {user.status === "active" && (
            <button type="button" className={BUTTON} disabled={busy} onClick={() => newLink("reset")}>
              Password reset link
            </button>
          )}
        </div>
        {link && (
          <div className="mt-4 max-w-xl">
            <OneTimeLinkPanel url={link.url} expiresAt={link.expires} kind={link.kind} />
          </div>
        )}
      </section>

      <section className={SECTION} aria-labelledby="access-title">
        <div className="flex flex-wrap items-baseline justify-between gap-4">
          <h2 id="access-title" className="font-display text-xl text-[var(--ink)]">
            Access
          </h2>
          {user.role === "user" && (
            <div className="flex items-center gap-3">
              {dirty && <span className="text-xs text-amber-700">Unsaved changes</span>}
              <button type="button" className={BUTTON} disabled={busy || !dirty} onClick={() => setDraft(detail.overrides)}>
                Discard
              </button>
              <button type="button" className={PRIMARY} disabled={busy || !dirty} onClick={savePermissions}>
                Save access
              </button>
            </div>
          )}
        </div>
        {user.role === "admin" ? (
          <p className="mt-2 text-sm text-[var(--muted)]">Admins can open every page and do everything; per-user access doesn&apos;t apply.</p>
        ) : (
          <>
            {user.status === "disabled" && (
              <p className="mt-2 max-w-3xl rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-[var(--ink)]">
                This account is disabled, so none of this applies until you enable it again.
              </p>
            )}
            <p className="mt-2 max-w-3xl text-sm text-[var(--muted)]">
              Default follows the standard for users. Allow or Deny overrides it for this person; Deny always wins.
              Changes apply on their next click; they don&apos;t need to sign in again.
            </p>
            <div className="mt-6">
              <PermissionEditor catalog={catalog} overrides={draft} saved={detail} onChange={setDraft} disabled={busy} />
            </div>
          </>
        )}
      </section>

      <section className={SECTION} aria-labelledby="activity-title">
        <div className="flex items-baseline justify-between">
          <h2 id="activity-title" className="font-display text-xl text-[var(--ink)]">
            Recent activity
          </h2>
          <Link href={`/admin/audit?actor=${encodeURIComponent(user.id)}`} className="text-sm font-medium text-[var(--accent)]">
            Full audit log →
          </Link>
        </div>
        {detail.recent_activity.length === 0 ? (
          <p className="mt-4 text-sm text-[var(--muted)]">Nothing recorded yet.</p>
        ) : (
          <ul className="mt-4 divide-y divide-slate-100 text-sm">
            {detail.recent_activity.map((e) => (
              <li key={e.id} className="flex flex-wrap justify-between gap-2 py-2">
                <span>
                  <code className="text-xs">{e.action}</code>
                  {e.outcome !== "success" && <span className="ml-2 text-xs text-red-700">{e.outcome}</span>}
                  <span className="ml-2 text-[var(--muted)]">by {e.actor_label || "system"}</span>
                </span>
                <span className="text-xs text-[var(--muted)]">{formatWhen(e.at)}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </PageContainer>
  );
}
