import "server-only";

import { cookies, headers } from "next/headers";

import { SESSION_COOKIE } from "@/lib/session-cookie";

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable ${name}. ` +
        "Copy frontend/.env.local.example to frontend/.env.local and set it."
    );
  }
  return value;
}

/** The browser's address as this server saw it: the last X-Forwarded-For
 *  hop (added by the nearest reverse proxy), else X-Real-IP. */
async function clientIp(): Promise<string | null> {
  const h = await headers();
  const forwarded = h.get("x-forwarded-for");
  if (forwarded) {
    const hops = forwarded.split(",").map((s) => s.trim()).filter(Boolean);
    if (hops.length) return hops[hops.length - 1];
  }
  return h.get("x-real-ip");
}

/**
 * Proxies a request to the FastAPI backend as the signed-in user: the
 * HttpOnly session cookie is forwarded as `Authorization: Session <token>`.
 * Without a cookie the request goes out unauthenticated and the backend
 * answers 401. Never import this module from client components.
 *
 * Sign-in and link endpoints also need the caller's address for rate
 * limiting; it is sent as X-Client-IP, which the backend trusts only with
 * the shared FRONTEND_PROXY_SECRET.
 */
export async function sastFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const base = requiredEnv("SAST_API_URL");
  const token = (await cookies()).get(SESSION_COOKIE)?.value;

  const extra: Record<string, string> = {};
  if (token) extra.Authorization = `Session ${token}`;
  const proxySecret = process.env.FRONTEND_PROXY_SECRET;
  const ip = proxySecret ? await clientIp() : null;
  if (proxySecret && ip) {
    extra["X-Frontend-Key"] = proxySecret;
    extra["X-Client-IP"] = ip;
  }
  const userAgent = (await headers()).get("user-agent");
  if (userAgent) extra["User-Agent"] = userAgent;

  return fetch(`${base}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...extra,
      ...(init.headers || {}),
    },
    cache: "no-store",
  });
}
