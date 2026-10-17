import { NextRequest, NextResponse } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";
import { SESSION_COOKIE, sessionCookieOptions } from "@/lib/session-cookie";

export const dynamic = "force-dynamic";

/** Create the first admin (only works while there are no users) and sign them in. */
export async function POST(request: NextRequest) {
  let res: Response;
  try {
    res = await sastFetch("/setup", { method: "POST", body: await request.text() });
  } catch (err) {
    return proxyFailure(err);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return NextResponse.json(data, { status: res.status });
  const { token, remember, expires_at, landing } = data as {
    token: string;
    remember: boolean;
    expires_at: string;
    landing: string;
  };
  const response = NextResponse.json({ redirect: landing });
  response.cookies.set(SESSION_COOKIE, token, sessionCookieOptions(remember, expires_at));
  return response;
}
