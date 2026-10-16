import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/** `remember` = the "Remember me" checkbox: whether to issue a persistent (vs. session) cookie. */
type Credentials = { email: string; password: string; remember?: boolean };

type AuthResult =
  | { ok: true }
  | { ok: false; reason: "invalid_credentials" | "not_configured" };

/**
 * AUTH INTEGRATION POINT.
 *
 * The app has no user authentication yet (the backend only checks the shared
 * SAST_API_TOKEN, attached server-side by lib/server-sast.ts). Until a real
 * identity provider or backend login endpoint is wired in here, this reports
 * "not_configured" and never signs anyone in.
 *
 * To integrate: verify `credentials` against your provider, issue a session
 * (e.g. an httpOnly, Secure, SameSite cookie) before returning `{ ok: true }`,
 * and return `invalid_credentials` for a wrong email/password.
 */
async function authenticate(credentials: Credentials): Promise<AuthResult> {
  void credentials;
  return { ok: false, reason: "not_configured" };
}

export async function POST(request: NextRequest) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "bad_request" }, { status: 400 });
  }

  const { email, password, remember } = (body ?? {}) as Partial<Credentials>;
  if (typeof email !== "string" || typeof password !== "string" || !email.trim() || !password) {
    return NextResponse.json({ error: "bad_request" }, { status: 400 });
  }

  const result = await authenticate({ email: email.trim(), password, remember: remember === true });
  if (result.ok) {
    return NextResponse.json({ ok: true });
  }
  if (result.reason === "not_configured") {
    return NextResponse.json({ error: "not_configured" }, { status: 501 });
  }
  return NextResponse.json({ error: "invalid_credentials" }, { status: 401 });
}
