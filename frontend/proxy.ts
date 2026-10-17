import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { isPublicPage } from "@/lib/access";
import { SESSION_COOKIE } from "@/lib/session-cookie";

/**
 * Runs before every page and API request. It only does cheap checks; the
 * backend decides who may do what on every API call, and page layouts ask
 * the backend whether the session is still valid.
 *
 * 1. Mutating /api calls must come from this site (Origin check). Together
 *    with the SameSite=Lax cookie this is the CSRF protection.
 * 2. No session cookie: pages redirect to /login?next=..., API calls get 401.
 * 3. Passes the requested path to layouts (x-sb-path) for the post-login return.
 */

const PUBLIC_API = ["/api/auth/login", "/api/auth/setup", "/api/setup"];
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function matches(path: string, prefixes: string[]): boolean {
  return prefixes.some((p) => path === p || path.startsWith(`${p}/`));
}

/** Origins this app is served from. APP_ORIGIN (comma separated) covers a
 *  reverse proxy whose public origin differs from what this server sees. */
function allowedOrigins(request: NextRequest): Set<string> {
  const origins = new Set([request.nextUrl.origin]);
  for (const o of (process.env.APP_ORIGIN ?? "").split(",")) {
    if (o.trim()) origins.add(o.trim().replace(/\/$/, ""));
  }
  return origins;
}

function sameOrigin(request: NextRequest): boolean {
  const origin = request.headers.get("origin");
  if (origin) return allowedOrigins(request).has(origin);
  // Browsers always send Origin on cross-site POSTs; without it, fall back to
  // Fetch Metadata and refuse anything a browser marks cross-site.
  const site = request.headers.get("sec-fetch-site");
  return site === "same-origin" || site === "none";
}

function json(status: number, code: string, detail: string): NextResponse {
  return NextResponse.json({ detail, code }, { status, headers: { "Cache-Control": "no-store" } });
}

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const isApi = pathname.startsWith("/api/");

  if (isApi && !SAFE_METHODS.has(request.method) && !sameOrigin(request)) {
    return json(403, "cross_origin", "Cross-site request refused.");
  }

  const isPublic = isApi ? matches(pathname, PUBLIC_API) : isPublicPage(pathname);
  if (!isPublic && !request.cookies.has(SESSION_COOKIE)) {
    if (isApi) return json(401, "unauthenticated", "Authentication required");
    const login = new URL("/login", request.url);
    if (pathname !== "/") login.searchParams.set("next", `${pathname}${search}`);
    return NextResponse.redirect(login);
  }

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-sb-path", `${pathname}${search}`);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  if (isApi) response.headers.set("Cache-Control", "private, no-store");
  return response;
}

export const config = {
  // Everything except Next's own assets and files with an extension (favicon, images).
  matcher: ["/((?!_next/static|_next/image|.*\\.[a-zA-Z0-9]+$).*)"],
};
