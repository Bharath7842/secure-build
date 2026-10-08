import { NextRequest } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

export const dynamic = "force-dynamic";

/**
 * Proxies the backend's SSE narration stream (`GET /scans/{id}/narration/stream`)
 * straight through — unlike the sibling `narration/route.ts`, this never buffers
 * the body into JSON, since the whole point is the client reading `thinking`/
 * `response`/`done` events as they arrive.
 */
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const step = request.nextUrl.searchParams.get("step") ?? "";
  try {
    const res = await sastFetch(`/scans/${id}/narration/stream?step=${encodeURIComponent(step)}`);
    if (!res.body) {
      return new Response(null, { status: res.status });
    }
    return new Response(res.body, {
      status: res.status,
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
        "X-Accel-Buffering": "no",
      },
    });
  } catch (err) {
    return proxyFailure(err);
  }
}
