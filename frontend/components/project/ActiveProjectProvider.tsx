"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { useAuth } from "@/components/auth/AuthProvider";
import { api } from "@/lib/api";
import type { Project } from "@/lib/types";

type ActiveProjectValue = {
  projects: Project[];
  loading: boolean;
  /** The project the scan menus and history pages are about, or null when none is chosen. */
  activeProject: Project | null;
  setActiveProjectId: (id: string | null) => void;
  /** Type of the scan whose detail page is open, so the sidebar can highlight its menu. */
  viewedScanType: string | null;
  setViewedScanType: (type: string | null) => void;
  /** Reload the list after a project is created, edited or deleted. */
  refresh: () => Promise<void>;
};

const ActiveProjectContext = createContext<ActiveProjectValue>({
  projects: [],
  loading: false,
  activeProject: null,
  setActiveProjectId: () => undefined,
  viewedScanType: null,
  setViewedScanType: () => undefined,
  refresh: async () => undefined,
});

/** A project named by the address: `?project_id=` or `/projects/<id>[/settings]`. */
function projectIdFromUrl(pathname: string, params: URLSearchParams): string | null {
  const fromQuery = params.get("project_id");
  if (fromQuery) return fromQuery;
  const match = /^\/projects\/([^/]+)/.exec(pathname);
  return match && match[1] !== "new" ? match[1] : null;
}

export function ActiveProjectProvider({ children }: { children: ReactNode }) {
  const me = useAuth();
  const pathname = usePathname();
  const params = useSearchParams();
  const storageKey = me ? `sb-active-project:${me.user.id}` : null;

  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [viewedScanType, setViewedScanType] = useState<string | null>(null);

  const urlId = projectIdFromUrl(pathname, params);
  const [lastUrlId, setLastUrlId] = useState<string | null>(urlId);
  // An address that names a project makes it the active one.
  if (urlId !== lastUrlId) {
    setLastUrlId(urlId);
    if (urlId) setActiveId(urlId);
  }

  const refresh = useCallback(async () => {
    try {
      setProjects(await api.projects.list());
    } catch {
      setProjects([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Pick up the remembered project (a per-viewer convenience, so storage may be unavailable).
  useEffect(() => {
    if (urlId) {
      setActiveId(urlId);
      return;
    }
    if (!storageKey) return;
    try {
      setActiveId(localStorage.getItem(storageKey));
    } catch {
      /* ignore */
    }
    // Only on first load and when the signed-in user changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [storageKey]);

  const activeProject = useMemo(() => {
    if (loading) return null;
    return projects.find((p) => p.id === activeId) ?? (projects.length === 1 ? projects[0] : null);
  }, [projects, activeId, loading]);

  // Remember the choice; forget one that no longer exists.
  useEffect(() => {
    if (!storageKey || loading) return;
    try {
      if (activeProject) localStorage.setItem(storageKey, activeProject.id);
      else localStorage.removeItem(storageKey);
    } catch {
      /* ignore */
    }
  }, [activeProject, storageKey, loading]);

  const value = useMemo(
    () => ({
      projects,
      loading,
      activeProject,
      setActiveProjectId: setActiveId,
      viewedScanType,
      setViewedScanType,
      refresh,
    }),
    [projects, loading, activeProject, viewedScanType, refresh],
  );
  return <ActiveProjectContext.Provider value={value}>{children}</ActiveProjectContext.Provider>;
}

export function useActiveProject(): ActiveProjectValue {
  return useContext(ActiveProjectContext);
}

/** `href` with the active project's id added, for links into project-scoped pages. */
export function withProject(href: string, projectId: string | null | undefined): string {
  if (!projectId) return href;
  return `${href}${href.includes("?") ? "&" : "?"}project_id=${encodeURIComponent(projectId)}`;
}
