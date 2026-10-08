import { NextRequest } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

export const dynamic = "force-dynamic";

/**
 * Proxies one DAST crawl screenshot straight through as binary image bytes — same
 * passthrough shape as the sibling `narration/stream` route, just without the
 * event-stream headers. The browser's `<img src>` points directly at this route;
 * the bearer token never reaches the client.
 */
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string; filename: string }> }
) {
  const { id, filename } = await params;
  try {
    const res = await sastFetch(`/scans/${id}/screenshots/${encodeURIComponent(filename)}`);
    if (!res.ok || !res.body) {
      return new Response(null, { status: res.status });
    }
    return new Response(res.body, {
      status: res.status,
      headers: {
        "Content-Type": "image/jpeg",
        "Cache-Control": "private, max-age=86400",
      },
    });
  } catch (err) {
    return proxyFailure(err);
  }
}
