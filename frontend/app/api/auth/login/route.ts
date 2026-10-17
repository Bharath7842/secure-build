import { NextRequest, NextResponse } from "next/server";

import { safeNextPath } from "@/lib/access";
import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";
import { SESSION_COOKIE, sessionCookieOptions } from "@/lib/session-cookie";

export const dynamic = "force-dynamic";

type SessionOut = {
  token: string;
  expires_at: string;
  remember: boolean;
  landing: string;
  pages: string[];
};

/**
 * Sign in. The backend checks the password, rate-limits, and returns a
 * session token, which goes into an HttpOnly cookie and is never sent to the
 * browser's JavaScript. The response says where to go next: the requested
 * `next` path if it's safe and permitted, else the user's landing page.
 */
export async function POST(request: NextRequest) {
  let body: { email?: unknown; password?: unknown; remember?: unknown; next?: unknown };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ detail: "Invalid request", code: "bad_request" }, { status: 400 });
  }
  const { email, password, remember, next } = body ?? {};
  if (typeof email !== "string" || typeof password !== "string" || !email.trim() || !password) {
    return NextResponse.json({ detail: "Invalid request", code: "bad_request" }, { status: 400 });
  }

  let res: Response;
  try {
    res = await sastFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email: email.trim(), password, remember: remember === true }),
    });
  } catch (err) {
    return proxyFailure(err);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const headers: Record<string, string> = {};
    const retry = res.headers.get("retry-after");
    if (retry) headers["Retry-After"] = retry;
    return NextResponse.json(data, { status: res.status, headers });
  }

  const session = data as SessionOut;
  const redirect = safeNextPath(typeof next === "string" ? next : null, session, request.nextUrl.origin);
  const response = NextResponse.json({ redirect });
  response.cookies.set(SESSION_COOKIE, session.token, sessionCookieOptions(session.remember, session.expires_at));
  return response;
}
