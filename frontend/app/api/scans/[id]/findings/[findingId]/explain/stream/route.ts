import { NextRequest } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string; findingId: string }> },
) {
  const { id, findingId } = await params;
  let body: string;
  try {
    body = await request.text();
  } catch {
    body = "{}";
  }
  try {
    const res = await sastFetch(`/scans/${id}/findings/${findingId}/explain/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
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