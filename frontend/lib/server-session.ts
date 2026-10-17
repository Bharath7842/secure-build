import "server-only";

import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { cache } from "react";

import { isPublicPage, pageKeyFor, type Me } from "@/lib/access";
import { sastFetch } from "@/lib/server-sast";
import { SESSION_COOKIE } from "@/lib/session-cookie";

/** Header proxy.ts sets to the requested path + query. */
export const REQUEST_PATH_HEADER = "x-sb-path";

/**
 * The signed-in user with their permissions and pages, or null. Asks the
 * backend once per render (React cache). Only the backend decides; nothing
 * here trusts the cookie's contents.
 */
export const getSession = cache(async (): Promise<Me | null> => {
  if (!(await cookies()).get(SESSION_COOKIE)) return null;
  try {
    const res = await sastFetch("/auth/me");
    if (!res.ok) return null;
    return (await res.json()) as Me;
  } catch {
    return null;
  }
});

function loginUrl(path: string, reason?: string): string {
  const params = new URLSearchParams();
  if (path && path !== "/") params.set("next", path);
  if (reason) params.set("reason", reason);
  const query = params.toString();
  return query ? `/login?${query}` : "/login";
}

/**
 * For the root layout, on every full page load: the session plus whether the
 * requested page is allowed. Redirects to sign-in when a protected page has
 * no valid session (an expired one adds reason=expired), and away from the
 * sign-in and setup pages when already signed in.
 */
export async function sessionForRequest(): Promise<{ me: Me | null; forbidden: boolean }> {
  const me = await getSession();
  const requested = (await headers()).get(REQUEST_PATH_HEADER) ?? "/";
  const pathname = requested.split("?")[0];

  if (!me) {
    if (!isPublicPage(pathname)) {
      const hadCookie = (await cookies()).has(SESSION_COOKIE);
      redirect(loginUrl(requested, hadCookie ? "expired" : undefined));
    }
    return { me: null, forbidden: false };
  }
  if (pathname === "/login" || pathname === "/setup") redirect(me.landing);
  const key = pageKeyFor(pathname);
  return { me, forbidden: !!key && !me.pages.includes(key) };
}
