import { NextRequest, NextResponse } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";
import { SESSION_COOKIE, sessionCookieOptions } from "@/lib/session-cookie";

export const dynamic = "force-dynamic";

/** Change your own password. The backend signs out your other sessions and
 *  gives this one a new token, which replaces the cookie. */
export async function POST(request: NextRequest) {
  let res: Response;
  try {
    res = await sastFetch("/auth/password", { method: "POST", body: await request.text() });
  } catch (err) {
    return proxyFailure(err);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return NextResponse.json(data, { status: res.status });
  const { token, remember, expires_at } = data as { token: string; remember: boolean; expires_at: string };
  const response = NextResponse.json({ ok: true });
  response.cookies.set(SESSION_COOKIE, token, sessionCookieOptions(remember, expires_at));
  return response;
}
