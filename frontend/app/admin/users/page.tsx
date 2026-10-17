"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import NewUserDialog from "@/components/admin/NewUserDialog";
import { RoleBadge, StatusBadge, formatWhen } from "@/components/admin/badges";
import PageContainer from "@/components/PageContainer";
import type { AppUser } from "@/lib/access";
import { ApiError, api } from "@/lib/api";
import { inputClass, selectClass } from "@/lib/formStyles";

type Filters = { q: string; role: string; status: string };

export default function AdminUsersPage() {
  const [filters, setFilters] = useState<Filters>({ q: "", role: "", status: "" });
  const [users, setUsers] = useState<AppUser[] | null>(null);
  const [nextCursor, setNextCursor] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    let active = true;
    // Debounce typing in the search box.
    const timer = setTimeout(() => {
      api.admin
        .users(filters)
        .then((page) => {
          if (!active) return;
          setUsers(page.items);
          setNextCursor(page.next_cursor);
          setError(null);
        })
        .catch((err) => active && setError(err instanceof ApiError ? err.message : "Could not load users."));
    }, 250);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [filters, reload]);

  async function loadMore() {
    if (nextCursor === null) return;
    try {
      const page = await api.admin.users({ ...filters, cursor: nextCursor });
      setUsers((prev) => [...(prev ?? []), ...page.items]);
      setNextCursor(page.next_cursor);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load more users.");
    }
  }

  const filtered = filters.q || filters.role || filters.status;

  return (
    <PageContainer>
      <div className="flex flex-wrap items-baseline justify-between gap-4">
        <div>
          <h1 className="font-display text-3xl text-[var(--ink)]">Users</h1>
          <p className="mt-2 text-sm text-[var(--muted)]">
            People who can sign in, their role, and whether their account is active.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowNew(true)}
          className="rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
        >
          New user
        </button>
      </div>

      <div className="mt-8 flex flex-wrap items-end gap-4" role="search">
        <label className="block w-full max-w-xs text-sm">
          <span className="text-[var(--muted)]">Search</span>
          <input
            type="search"
            className={inputClass}
            placeholder="Name or email"
            value={filters.q}
            onChange={(e) => setFilters((f) => ({ ...f, q: e.target.value }))}
          />
        </label>
        <label className="block text-sm">
          <span className="text-[var(--muted)]">Role</span>
          <select className={selectClass} value={filters.role} onChange={(e) => setFilters((f) => ({ ...f, role: e.target.value }))}>
            <option value="">All roles</option>
            <option value="admin">Admin</option>
            <option value="user">User</option>
          </select>
        </label>
        <label className="block text-sm">
          <span className="text-[var(--muted)]">Status</span>
          <select className={selectClass} value={filters.status} onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}>
            <option value="">Any status</option>
            <option value="active">Active</option>
            <option value="invited">Invited</option>
            <option value="disabled">Disabled</option>
          </select>
        </label>
      </div>

      {error && (
        <div role="alert" className="mt-6 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {users === null && !error ? (
        <p className="mt-10 text-sm text-[var(--muted)]">Loading users…</p>
      ) : users && users.length === 0 ? (
        <div className="mt-10 rounded-md border border-slate-200 bg-white/60 px-6 py-10 text-center text-sm text-[var(--muted)]">
          {filtered ? "No users match these filters. Try clearing the search or picking another status." : "Only you so far. Add your team with New user."}
        </div>
      ) : users ? (
        <div className="mt-8 overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-[var(--muted)]">
                <th className="py-2 font-medium">Name</th>
                <th className="py-2 font-medium">Role</th>
                <th className="py-2 font-medium">Status</th>
                <th className="py-2 font-medium">Last sign-in</th>
                <th className="py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-slate-100">
                  <td className="py-3">
                    <Link href={`/admin/users/${u.id}`} className="font-medium text-[var(--ink)] hover:text-[var(--accent)]">
                      {u.display_name || u.email}
                    </Link>
                    {u.display_name && <p className="text-xs text-[var(--muted)]">{u.email}</p>}
                  </td>
                  <td className="py-3">
                    <RoleBadge role={u.role} />
                  </td>
                  <td className="py-3">
                    <StatusBadge status={u.status} />
                  </td>
                  <td className="py-3 text-[var(--muted)]">{formatWhen(u.last_login_at)}</td>
                  <td className="py-3 text-[var(--muted)]">{formatWhen(u.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {nextCursor !== null && (
            <button type="button" onClick={loadMore} className="mt-4 text-sm font-medium text-[var(--accent)]">
              Show more
            </button>
          )}
        </div>
      ) : null}

      {showNew && <NewUserDialog onClose={() => setShowNew(false)} onCreated={() => setReload((n) => n + 1)} />}
    </PageContainer>
  );
}
