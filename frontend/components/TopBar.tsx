"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { useAuth } from "@/components/auth/AuthProvider";
import { useActiveProject } from "@/components/project/ActiveProjectProvider";

/** Closes `onClose` on an outside click or Escape while `open`. */
function useDismiss(open: boolean, onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onPointer = (e: PointerEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, onClose]);
  return ref;
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      className={`shrink-0 text-[var(--muted)] transition-transform ${open ? "rotate-180" : ""}`}
    >
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}

function FolderIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      className="shrink-0 text-[var(--muted)]"
    >
      <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
    </svg>
  );
}

const MENU_PANEL =
  "absolute top-full z-30 mt-2 rounded-lg border border-slate-200 bg-white p-1 shadow-lg ring-1 ring-black/5";
const MENU_ITEM =
  "block w-full rounded-md px-3 py-2 text-left text-sm text-[var(--ink)] transition-colors hover:bg-slate-100";

/** Which project the scan menus and histories are about. */
function ProjectPicker() {
  const { projects, activeProject, setActiveProjectId, loading } = useActiveProject();
  const me = useAuth();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const ref = useDismiss(open, () => setOpen(false));

  const q = query.trim().toLowerCase();
  const shown = q ? projects.filter((p) => p.name.toLowerCase().includes(q)) : projects;

  return (
    <div ref={ref} className="relative min-w-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-label="Project"
        className="flex max-w-[22rem] items-center gap-2 rounded-md border border-slate-200 bg-white px-3 py-1.5 text-sm text-[var(--ink)] transition-colors hover:border-slate-300 hover:bg-slate-50"
      >
        <FolderIcon />
        <span className="hidden text-xs font-semibold uppercase tracking-wide text-[var(--muted)] sm:inline">
          Project
        </span>
        <span className="min-w-0 truncate font-medium">
          {loading ? "Loading…" : activeProject ? activeProject.name : "Select a project"}
        </span>
        <Chevron open={open} />
      </button>
      {open && (
        <div className={`${MENU_PANEL} left-0 w-72`}>
          {projects.length > 6 && (
            <input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search projects"
              aria-label="Search projects"
              className="mb-1 w-full rounded-md border border-slate-200 px-3 py-1.5 text-sm focus:border-[var(--accent)] focus:outline-none"
            />
          )}
          <ul role="listbox" className="max-h-72 overflow-y-auto">
            {shown.map((p) => {
              const selected = p.id === activeProject?.id;
              return (
                <li key={p.id} role="option" aria-selected={selected}>
                  <button
                    type="button"
                    onClick={() => {
                      setActiveProjectId(p.id);
                      setOpen(false);
                      setQuery("");
                    }}
                    className={`${MENU_ITEM} flex items-center justify-between gap-2 ${selected ? "font-medium" : ""}`}
                  >
                    <span className="truncate">{p.name}</span>
                    {selected && <span className="text-xs text-[var(--accent)]">Active</span>}
                  </button>
                </li>
              );
            })}
            {shown.length === 0 && (
              <li className="px-3 py-2 text-sm text-[var(--muted)]">
                {projects.length === 0 ? "No projects yet" : "No projects found"}
              </li>
            )}
          </ul>
          <div className="mt-1 border-t border-slate-100 pt-1">
            <Link href="/projects" onClick={() => setOpen(false)} className={MENU_ITEM}>
              All projects
            </Link>
            {me?.pages.includes("page.project_new") && (
              <Link
                href="/projects/new"
                onClick={() => setOpen(false)}
                className={`${MENU_ITEM} font-medium text-[var(--accent)]`}
              >
                + New project
              </Link>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/** Who is signed in, a link to their account, and sign out. */
function UserMenu() {
  const me = useAuth();
  const [open, setOpen] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const ref = useDismiss(open, () => setOpen(false));
  if (!me) return null;
  const name = me.user.display_name || me.user.email;

  async function signOut() {
    setSigningOut(true);
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      // Full navigation: nothing from the signed-in session stays in memory.
      window.location.assign("/login");
    }
  }

  return (
    <div ref={ref} className="relative shrink-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="menu"
        className="flex items-center gap-2.5 rounded-md py-1 pl-1 pr-2 transition-colors hover:bg-slate-100"
      >
        <span
          aria-hidden
          className="flex h-8 w-8 items-center justify-center rounded-full bg-[var(--sidebar)] text-sm font-semibold uppercase text-white"
        >
          {name.charAt(0)}
        </span>
        <span className="hidden max-w-[11rem] truncate text-sm font-medium text-[var(--ink)] sm:block" title={me.user.email}>
          {name}
        </span>
        <Chevron open={open} />
      </button>
      {open && (
        <div role="menu" className={`${MENU_PANEL} right-0 w-64`}>
          <div className="border-b border-slate-100 px-3 py-2">
            <p className="truncate text-sm font-medium text-[var(--ink)]">{name}</p>
            <p className="truncate text-xs text-[var(--muted)]">{me.user.email}</p>
            <p className="mt-0.5 text-xs text-[var(--muted)]">{me.user.role === "admin" ? "Admin" : "User"}</p>
          </div>
          <div className="pt-1">
            <Link href="/account" role="menuitem" onClick={() => setOpen(false)} className={MENU_ITEM}>
              Account
            </Link>
            <button
              type="button"
              role="menuitem"
              onClick={signOut}
              disabled={signingOut}
              className={`${MENU_ITEM} disabled:opacity-60`}
            >
              {signingOut ? "Signing out…" : "Sign out"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function TopBar() {
  return (
    <header className="relative z-20 flex h-14 shrink-0 items-center justify-between gap-4 border-b border-slate-200 bg-white px-6">
      <ProjectPicker />
      <UserMenu />
    </header>
  );
}
