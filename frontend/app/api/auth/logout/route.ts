import { NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";
import { SESSION_COOKIE, sessionCookieOptions } from "@/lib/session-cookie";

export const dynamic = "force-dynamic";

/** Sign out: end the session on the backend, drop the cookie and ask the
 *  browser to forget cached pages. Clears the cookie even if the backend
 *  can't be reached. */
export async function POST() {
  try {
    await sastFetch("/auth/logout", { method: "POST" });
  } catch {
    /* the cookie is cleared below either way */
  }
  const response = new NextResponse(null, { status: 204, headers: { "Clear-Site-Data": '"cache"' } });
  response.cookies.set(SESSION_COOKIE, "", { ...sessionCookieOptions(false), maxAge: 0 });
  return response;
}
