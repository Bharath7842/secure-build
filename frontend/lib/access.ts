/**
 * App accounts: the signed-in user and what they may see and do. (Not to be
 * confused with lib/roles.ts, which is about the identities a DAST scan logs
 * into a *target* app with.)
 *
 * Everything here is for showing and hiding UI. The backend enforces every
 * permission on its own; hiding a button is never the protection.
 */

export type AppRole = "admin" | "user";

export type AppUser = {
  id: string;
  email: string;
  display_name: string;
  role: AppRole;
  status: "active" | "invited" | "disabled";
  last_login_at?: string | null;
  created_at?: string | null;
};

/** GET /api/auth/me */
export type Me = {
  user: AppUser;
  /** Action keys, e.g. "scans.create". */
  permissions: string[];
  /** Page keys, e.g. "page.history". */
  pages: string[];
  /** Where to send the user after sign-in. */
  landing: string;
};

/** Pages anyone may open without signing in. */
export const PUBLIC_PAGES = ["/login", "/setup", "/account/setup"];

export function isPublicPage(path: string): boolean {
  return PUBLIC_PAGES.some((p) => path === p || path.startsWith(`${p}/`));
}

/** Which page key guards which route. The first matching prefix wins, so
 *  more specific routes come first. Routes not listed only need a session. */
export const PAGE_ROUTES: ReadonlyArray<{ key: string; match: (path: string) => boolean }> = [
  { key: "page.project_new", match: (p) => p === "/projects/new" },
  { key: "page.project_settings", match: (p) => /^\/projects\/[^/]+\/settings\/?$/.test(p) },
  { key: "page.projects", match: (p) => p === "/projects" || p.startsWith("/projects/") },
  { key: "page.scan_sast", match: (p) => p === "/scans/new" },
  { key: "page.history", match: (p) => p === "/scans" || p.startsWith("/scans/") },
  { key: "page.scan_sca", match: (p) => p === "/sca" || p.startsWith("/sca/") },
  { key: "page.scan_sbom", match: (p) => p === "/sbom" || p.startsWith("/sbom/") },
  { key: "page.settings", match: (p) => p === "/dast/settings" || p === "/settings" || p.startsWith("/settings/") },
  { key: "page.dast", match: (p) => p === "/dast" || p.startsWith("/dast/") },
  { key: "page.feedback", match: (p) => p === "/feedback" || p.startsWith("/feedback/") },
  { key: "page.admin_audit", match: (p) => p === "/admin/audit" || p.startsWith("/admin/audit/") },
  { key: "page.admin_users", match: (p) => p === "/admin" || p.startsWith("/admin/") },
];

/** The page key `path` needs, or null when a session is enough. */
export function pageKeyFor(path: string): string | null {
  return PAGE_ROUTES.find((r) => r.match(path))?.key ?? null;
}

/**
 * A safe place to go after signing in: a same-origin path the user may see,
 * else their landing page. Rejects other origins, protocol-relative and
 * backslash tricks ("//evil", "/\\evil"), and the auth pages themselves.
 */
export function safeNextPath(next: string | null | undefined, me: Pick<Me, "pages" | "landing">, origin: string): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return me.landing;
  let url: URL;
  try {
    url = new URL(next, origin);
  } catch {
    return me.landing;
  }
  if (url.origin !== origin) return me.landing;
  if (isPublicPage(url.pathname)) return me.landing;
  const key = pageKeyFor(url.pathname);
  if (key && !me.pages.includes(key)) return me.landing;
  return `${url.pathname}${url.search}${url.hash}`;
}

/** Whether to offer Stop/Pause on `scan` (display only; the backend decides). */
export function canStopScan(me: Me | null, scan: { created_by_user_id?: string | null }): boolean {
  if (!me) return false;
  if (me.permissions.includes("scans.cancel_any")) return true;
  return me.permissions.includes("scans.cancel_own") && !!scan.created_by_user_id && scan.created_by_user_id === me.user.id;
}

// --- Account and admin API shapes ------------------------------------------------------------

export type PermissionEntry = {
  key: string;
  kind: "page" | "action";
  label: string;
  description: string;
  user_default: boolean;
  grantable_to_user: boolean;
  requires: string[];
};

export type Override = "grant" | "deny";

/** A user's access as the admin pages show it. */
export type UserAccess = {
  overrides: Record<string, Override>;
  effective: string[];
  inactive: { key: string; missing: string[] }[];
};

export type AuditEvent = {
  id: string;
  at: string;
  actor_user_id: string | null;
  actor_label: string;
  action: string;
  outcome: "success" | "failure" | "denied";
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  details: Record<string, unknown>;
};

export type UserDetail = UserAccess & { user: AppUser; recent_activity: AuditEvent[] };

export type OneTimeLink = { url: string; expires_at: string };

export type SessionInfo = {
  id: string;
  created_at: string;
  last_seen_at: string;
  ip: string | null;
  user_agent: string | null;
  remember: boolean;
  current: boolean;
};

export type Page<T> = { items: T[]; next_cursor: number | null };

/** Who started a scan, as the scan lists show it: "You" for your own,
 *  the person's name, "CI (Jenkins)" for pipeline scans, or "Before
 *  accounts" for scans from before sign-in existed. */
export function startedByLabel(
  scan: { created_by_user_id?: string | null; created_by_name?: string | null; triggered_by?: string | null },
  me: Me | null,
): string {
  if (scan.created_by_user_id) {
    if (me && scan.created_by_user_id === me.user.id) return "You";
    return scan.created_by_name || "Unknown user";
  }
  return scan.triggered_by === "jenkins" ? "CI (Jenkins)" : "Before accounts";
}
