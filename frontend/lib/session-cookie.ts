/**
 * The session cookie: an opaque token the backend issued at sign-in. It is
 * HttpOnly, so client code never sees it; the Next.js server forwards it to
 * the backend as `Authorization: Session <token>` (see lib/server-sast.ts).
 *
 * Shared by proxy.ts and the route handlers, so it must not import
 * server-only modules.
 */

/** Secure cookies need HTTPS. On by default in production; set
 *  SESSION_COOKIE_SECURE=false to run a production build over plain http. */
export const SESSION_COOKIE_SECURE =
  (process.env.SESSION_COOKIE_SECURE ?? (process.env.NODE_ENV === "production" ? "true" : "false")) === "true";

/** `__Host-` makes the browser refuse the cookie unless it is Secure,
 *  host-only and Path=/, which only works over HTTPS. */
export const SESSION_COOKIE = SESSION_COOKIE_SECURE ? "__Host-sb_session" : "sb_session";

type CookieOptions = {
  httpOnly: true;
  secure: boolean;
  sameSite: "lax";
  path: "/";
  expires?: Date;
};

/** Options for setting the session cookie. Without "remember me" it is a
 *  browser-session cookie; with it, it lasts until the session's hard expiry. */
export function sessionCookieOptions(remember: boolean, expiresAt?: string): CookieOptions {
  const options: CookieOptions = { httpOnly: true, secure: SESSION_COOKIE_SECURE, sameSite: "lax", path: "/" };
  if (remember && expiresAt) options.expires = new Date(expiresAt);
  return options;
}
