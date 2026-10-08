import { NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

/**
 * Proxy helper for the DAST routes. Server-only (it pulls in the bearer token
 * through `sastFetch`): never import this module from a client component.
 *
 * Status mapping the UI relies on:
 *  - backend answered: its status and JSON body pass through (a wrong token is a 401);
 *  - backend unreachable or answered with non-JSON: 502;
 *  - this server is missing SAST_API_URL / SAST_API_TOKEN: 500 naming the variable.
 */
/** Map a thrown proxy error to the status the UI relies on: a missing server-side env var is a
 *  500 naming the variable; anything else (backend down, bad response) is a 502. */
export function proxyFailure(err: unknown): NextResponse {
  const message = err instanceof Error ? err.message : "";
  if (message.startsWith("Missing required environment variable")) {
    return NextResponse.json({ detail: message }, { status: 500 });
  }
  return NextResponse.json({ detail: "Could not reach the backend API." }, { status: 502 });
}

export async function dastProxy(path: string, init: RequestInit = {}): Promise<NextResponse> {
  let res: Response;
  try {
    res = await sastFetch(path, init);
  } catch (err) {
    return proxyFailure(err);
  }

  const text = await res.text();
  if (res.status === 204 || text === "") {
    return new NextResponse(null, { status: res.status });
  }

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return NextResponse.json(
      { detail: `The backend API returned an unexpected response (status ${res.status}).` },
      { status: 502 },
    );
  }
  return NextResponse.json(body, { status: res.status });
}
