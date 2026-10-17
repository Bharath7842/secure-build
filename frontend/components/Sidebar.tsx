"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { Suspense, createContext, useContext, useEffect, useState } from "react";

import { useAuth } from "@/components/auth/AuthProvider";
import { useActiveProject, withProject } from "@/components/project/ActiveProjectProvider";
import type { Project } from "@/lib/types";

const STORAGE_KEY = "sidebar-collapsed";

type NavItem = {
  href: string;
  label: string;
  short: string;
  exact?: boolean;
  /** Extra paths that should highlight this nav item */
  matchPaths?: string[];
  isActive?: (pathname: string) => boolean;
  /** Page key (lib/access.ts) the user needs for this link to show. */
  page?: string;
  icon?:
    | "folder"
    | "plus"
    | "play"
    | "clock"
    | "overview"
    | "findings"
    | "settings"
    | "lock"
    | "cloud"
    | "package"
    | "layers"
    | "shield"
    | "target"
    | "users"
    | "audit"
    | "user"
    | "logout";
};

function NavIcon({ name }: { name: NonNullable<NavItem["icon"]> }) {
  const props = {
    xmlns: "http://www.w3.org/2000/svg",
    width: 16,
    height: 16,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.75,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true as const,
    className: "shrink-0 opacity-90",
  };

  switch (name) {
    case "folder":
      return (
        <svg {...props}>
          <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
        </svg>
      );
    case "plus":
      return (
        <svg {...props}>
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <path d="M12 8v8M8 12h8" />
        </svg>
      );
    case "play":
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="10" />
          <path d="M10 8l6 4-6 4V8z" fill="currentColor" stroke="none" />
        </svg>
      );
    case "clock":
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="10" />
          <path d="M12 6v6l4 2" />
        </svg>
      );
    case "overview":
      return (
        <svg {...props}>
          <rect x="3" y="3" width="7" height="7" rx="1" />
          <rect x="14" y="3" width="7" height="7" rx="1" />
          <rect x="3" y="14" width="7" height="7" rx="1" />
          <rect x="14" y="14" width="7" height="7" rx="1" />
        </svg>
      );
    case "findings":
      return (
        <svg {...props}>
          <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
          <path d="M12 9v4M12 17h.01" />
        </svg>
      );
    case "settings":
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="3" />
          <path d="M12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4" />
        </svg>
      );
    case "lock":
      return (
        <svg {...props}>
          <rect x="5" y="11" width="14" height="10" rx="2" />
          <path d="M8 11V7a4 4 0 0 1 8 0v4" />
        </svg>
      );
    case "cloud":
      return (
        <svg {...props}>
          <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z" />
        </svg>
      );
    case "package":
      return (
        <svg {...props}>
          <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z" />
          <path d="m3.27 6.96 8.73 5.05 8.73-5.05M12 22.08V12" />
        </svg>
      );
    case "layers":
      return (
        <svg {...props}>
          <path d="m12 2 8.5 5-8.5 5-8.5-5L12 2Z" />
          <path d="m3.5 12 8.5 5 8.5-5" />
          <path d="m3.5 17 8.5 5 8.5-5" />
        </svg>
      );
    case "shield":
      return (
        <svg {...props}>
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
        </svg>
      );
    case "users":
      return (
        <svg {...props}>
          <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
          <circle cx="9" cy="7" r="4" />
          <path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75" />
        </svg>
      );
    case "audit":
      return (
        <svg {...props}>
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <path d="M14 2v6h6M8 13h8M8 17h5" />
        </svg>
      );
    case "user":
      return (
        <svg {...props}>
          <circle cx="12" cy="8" r="4" />
          <path d="M4 21v-1a7 7 0 0 1 14 0v1" />
        </svg>
      );
    case "logout":
      return (
        <svg {...props}>
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" />
        </svg>
      );
    case "target":
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="9" />
          <circle cx="12" cy="12" r="5" />
          <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
        </svg>
      );
  }
}

/** A scan type's dropdown: one entry to start a scan, one for that type's own history. */
type NavGroup = {
  id: string;
  label: string;
  short: string;
  icon: NonNullable<NavItem["icon"]>;
  /** Children the user may not see are dropped; a group with none left is hidden. */
  children: NavItem[];
  /** Why this type can't start a scan for the project, or null when it can. */
  blocker: (project: Project) => string | null;
};

const NEEDS_REPO = "Add a repository in the project's details";
const hasRepo = (p: Project) => !!p.default_git_url?.trim();

const SCAN_GROUPS: NavGroup[] = [
  {
    id: "sast",
    label: "SAST",
    short: "AS",
    icon: "play",
    blocker: (p) => (!hasRepo(p) ? NEEDS_REPO : !p.enable_sast ? "SAST is turned off in project settings" : null),
    children: [
      { href: "/scans/new", label: "New scan", short: "N", icon: "plus", page: "page.scan_sast" },
      {
        href: "/scans",
        label: "Scan history",
        short: "H",
        icon: "clock",
        page: "page.history",
        // Exact, so /scans/new (a sibling) does not light it up; isActive adds the detail pages.
        exact: true,
        // The list and the scan detail pages; not /scans/new.
        isActive: (p) => p === "/scans" || (p.startsWith("/scans/") && !p.startsWith("/scans/new")),
      },
    ],
  },
  {
    id: "sca",
    label: "SCA",
    short: "SCA",
    icon: "package",
    blocker: (p) => (!hasRepo(p) ? NEEDS_REPO : !p.enable_sca ? "SCA is turned off in project settings" : null),
    children: [
      { href: "/scans/new?type=sca", label: "New scan", short: "N", icon: "plus", page: "page.scan_sast" },
      { href: "/sca", label: "Scan history", short: "H", icon: "clock", page: "page.scan_sca" },
    ],
  },
  {
    id: "sbom",
    label: "SBOM",
    short: "SB",
    icon: "layers",
    blocker: (p) => (!hasRepo(p) ? NEEDS_REPO : !p.enable_sbom ? "SBOM is turned off in project settings" : null),
    children: [
      { href: "/scans/new?type=sbom", label: "New scan", short: "N", icon: "plus", page: "page.scan_sast" },
      { href: "/sbom", label: "Scan history", short: "H", icon: "clock", page: "page.scan_sbom" },
    ],
  },
  {
    id: "dast",
    label: "DAST",
    short: "DA",
    icon: "target",
    // DAST scans a URL entered per scan, so the project needs no repository.
    blocker: () => null,
    children: [
      { href: "/scans/new?type=dast", label: "New scan", short: "N", icon: "plus", page: "page.scan_sast" },
      { href: "/dast", label: "Scan history", short: "H", icon: "clock", page: "page.dast" },
    ],
  },
];

const SAST_LINKS: NavItem[] = [
  { href: "/feedback", label: "Feedback & Review", short: "FR", exact: true, icon: "findings", page: "page.feedback" },
  {
    href: "/projects",
    label: "Projects",
    short: "Pr",
    exact: true,
    icon: "folder",
    page: "page.projects",
    // Exact list + project detail pages; do not steal /projects/new
    isActive: (p) => p === "/projects" || (p.startsWith("/projects/") && !p.startsWith("/projects/new")),
  },
  { href: "/projects/new", label: "New Project", short: "NP", exact: true, icon: "plus", page: "page.project_new" },
  { href: "/settings", label: "Settings", short: "Se", exact: true, icon: "settings", page: "page.settings" },
];

const ADMIN_LINKS: NavItem[] = [
  { href: "/admin/users", label: "Users", short: "Us", icon: "users", page: "page.admin_users" },
  { href: "/admin/audit", label: "Audit log", short: "Au", icon: "audit", page: "page.admin_audit" },
];

const SidebarContext = createContext(false);

function itemIsActive(pathname: string, item: NavItem): boolean {
  return (
    (item.isActive?.(pathname) ?? false) ||
    (item.exact
      ? pathname === item.href
      : pathname === item.href || pathname.startsWith(`${item.href}/`)) ||
    (item.matchPaths?.some((p) => pathname === p || pathname.startsWith(`${p}/`)) ?? false)
  );
}

function NavLink({
  href,
  label,
  short,
  exact,
  matchPaths,
  isActive,
  icon,
  active: activeOverride,
  indent,
}: NavItem & { active?: boolean; indent?: boolean }) {
  const pathname = usePathname();
  const collapsed = useContext(SidebarContext);
  const active = activeOverride ?? itemIsActive(pathname, { href, label, short, exact, matchPaths, isActive });

  return (
    <Link
      href={href}
      title={collapsed ? label : undefined}
      className={`flex items-center gap-2.5 rounded-md py-2 text-sm transition-colors ${
        collapsed ? "justify-center px-2" : indent ? "pl-9 pr-3" : "px-3"
      } ${
        active
          ? "bg-white/15 font-medium text-white"
          : "text-slate-300 hover:bg-white/10 hover:text-white"
      }`}
    >
      {collapsed ? (
        icon ? (
          <NavIcon name={icon} />
        ) : (
          <span className="text-xs font-semibold tracking-wide">{short}</span>
        )
      ) : (
        <>
          {icon && <NavIcon name={icon} />}
          {label}
        </>
      )}
    </Link>
  );
}

/** The four "New scan" links share /scans/new, so the scan type in `?type=` tells them apart. */
function childIsActive(
  pathname: string,
  params: URLSearchParams,
  item: NavItem,
  groupId: string,
  viewedScanType: string | null,
): boolean {
  // A scan's detail page belongs to the menu of that scan's type.
  if (pathname.startsWith("/scans/") && !pathname.startsWith("/scans/new")) {
    return !item.href.startsWith("/scans/new") && groupId === (viewedScanType ?? "sast");
  }
  if (item.href.startsWith("/scans/new")) {
    const itemType = new URLSearchParams(item.href.split("?")[1] ?? "").get("type") ?? "sast";
    return pathname === "/scans/new" && (params.get("type") ?? "sast") === itemType;
  }
  return itemIsActive(pathname, item);
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
      className={`ml-auto shrink-0 opacity-70 transition-transform ${open ? "rotate-90" : ""}`}
    >
      <path d="M9 18l6-6-6-6" />
    </svg>
  );
}

function NavGroupItem({
  group,
  items,
  project,
  open,
  onToggle,
}: {
  group: NavGroup;
  items: NavItem[];
  project: Project;
  open: boolean;
  onToggle: () => void;
}) {
  const pathname = usePathname();
  const params = useSearchParams();
  const me = useAuth();
  const collapsed = useContext(SidebarContext);
  const { viewedScanType } = useActiveProject();
  const anyActive = items.some((item) => childIsActive(pathname, params, item, group.id, viewedScanType));
  const blocked = group.blocker(project);
  // The repository URL is edited on the project page.
  const settingsHref = me?.permissions.includes("projects.manage") ? `/projects/${project.id}` : null;

  const scoped = items.map((item) => ({ ...item, href: withProject(item.href, project.id) }));

  // No room for a submenu in the icon rail: the icon goes to the type's history.
  if (collapsed) {
    const target = scoped[scoped.length - 1];
    return (
      <NavLink href={target.href} label={group.label} short={group.short} icon={group.icon} active={anyActive} />
    );
  }

  const panelId = `nav-group-${group.id}`;
  return (
    <div>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={panelId}
        className="flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-sm text-slate-300 transition-colors hover:bg-white/10 hover:text-white"
      >
        <NavIcon name={group.icon} />
        {group.label}
        <Chevron open={open} />
      </button>
      {open && (
        <div id={panelId} className="mt-1 flex flex-col gap-1">
          {scoped.map((item, i) => {
            const isNew = items[i].href.startsWith("/scans/new");
            if (isNew && blocked) {
              const cls = "flex items-center rounded-md py-2 pl-9 pr-3 text-sm text-slate-500";
              return settingsHref ? (
                <Link key={item.href} href={settingsHref} title={blocked} className={`${cls} hover:text-slate-300`}>
                  {item.label}
                  <span className="ml-auto text-[10px] uppercase tracking-wide">Set up</span>
                </Link>
              ) : (
                <span key={item.href} title={blocked} aria-disabled className={`${cls} cursor-not-allowed`}>
                  {item.label}
                </span>
              );
            }
            return (
              <NavLink
                key={item.href}
                {...item}
                icon={undefined}
                indent
                active={childIsActive(pathname, params, items[i], group.id, viewedScanType)}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}

function ToggleIcon({ collapsed }: { collapsed: boolean }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      {collapsed ? <path d="M9 18l6-6-6-6" /> : <path d="M15 18l-6-6 6-6" />}
    </svg>
  );
}

export default function Sidebar() {
  const me = useAuth();
  const { activeProject, loading: loadingProjects, viewedScanType } = useActiveProject();
  const pathname = usePathname();
  const params = useSearchParams();
  const visible = (item: NavItem) => !item.page || !!me?.pages.includes(item.page);
  const adminLinks = ADMIN_LINKS.filter(visible);

  // One menu open at a time: opening a menu closes the previous one, and
  // landing on a page opens the menu it belongs to.
  const activeGroupId =
    SCAN_GROUPS.find((g) =>
      g.children.filter(visible).some((item) => childIsActive(pathname, params, item, g.id, viewedScanType)),
    )?.id ?? null;
  const [openGroup, setOpenGroup] = useState<string | null>(activeGroupId);
  const [lastActiveGroup, setLastActiveGroup] = useState<string | null>(activeGroupId);
  if (activeGroupId !== lastActiveGroup) {
    setLastActiveGroup(activeGroupId);
    if (activeGroupId) setOpenGroup(activeGroupId);
  }
  const [collapsed, setCollapsed] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    try {
      setCollapsed(localStorage.getItem(STORAGE_KEY) === "true");
    } catch {
      /* ignore */
    }
    setMounted(true);
  }, []);

  function toggleCollapsed() {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(STORAGE_KEY, String(next));
      } catch {
        /* ignore */
      }
      return next;
    });
  }

  return (
    <SidebarContext.Provider value={collapsed}>
      <aside
        className={`flex h-full flex-shrink-0 flex-col bg-[var(--sidebar)] py-8 text-slate-100 transition-[width,padding] duration-300 ease-in-out ${
          collapsed ? "w-[4.25rem] px-3" : "w-64 px-6"
        } ${mounted ? "" : "w-64 px-6"}`}
      >
        <div className={`flex items-center ${collapsed ? "flex-col gap-3" : "justify-between gap-2"}`}>
          <Link
            href={me?.landing ?? "/"}
            className={`whitespace-nowrap font-display tracking-wide text-white transition-all ${
              collapsed ? "text-lg" : "text-2xl"
            }`}
            title={collapsed ? "Secure Build" : undefined}
          >
            {!collapsed && "Secure Build"}
          </Link>
          <button
            type="button"
            onClick={toggleCollapsed}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-expanded={!collapsed}
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-slate-400 transition-colors hover:bg-white/10 hover:text-white"
          >
            <ToggleIcon collapsed={collapsed} />
          </button>
        </div>

        <nav className="sidebar-scroll mt-8 flex min-h-0 flex-1 flex-col gap-1 overflow-y-auto overflow-x-hidden">
          <Suspense fallback={null}>
            {activeProject ? (
              SCAN_GROUPS.map((group) => {
                const items = group.children.filter(visible);
                return items.length > 0 ? (
                  <NavGroupItem
                    key={group.id}
                    group={group}
                    items={items}
                    project={activeProject}
                    open={openGroup === group.id}
                    onToggle={() => setOpenGroup((cur) => (cur === group.id ? null : group.id))}
                  />
                ) : null;
              })
            ) : (
              !loadingProjects &&
              !collapsed && (
                <p className="px-3 py-2 text-xs leading-relaxed text-slate-400">
                  Select or create a project to start scanning.
                </p>
              )
            )}
          </Suspense>
          {SAST_LINKS.filter(visible).map((link) => (
            <NavLink key={link.href} {...link} />
          ))}
          {adminLinks.length > 0 && (
            <>
              {!collapsed && (
                <p className="mt-6 mb-1 px-3 text-xs font-semibold uppercase tracking-wide text-slate-400">Admin</p>
              )}
              {collapsed && <div className="my-3 border-t border-white/10" aria-hidden />}
              {adminLinks.map((link) => (
                <NavLink key={link.href} {...link} />
              ))}
            </>
          )}
        </nav>
      </aside>
    </SidebarContext.Provider>
  );
}
