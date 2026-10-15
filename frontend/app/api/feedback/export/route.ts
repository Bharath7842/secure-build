import { NextRequest, NextResponse } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

export const dynamic = "force-dynamic";

/** Labelled-data export (JSONL or CSV) for the learning phase. */
export async function GET(request: NextRequest) {
  try {
    const res = await sastFetch(`/feedback/export${request.nextUrl.search}`);
    if (!res.ok) {
      const body = await res.json().catch(() => ({ detail: "Export failed" }));
      return NextResponse.json(body, { status: res.status });
    }
    return new NextResponse(await res.arrayBuffer(), {
      status: 200,
      headers: {
        "Content-Type": res.headers.get("content-type") || "application/octet-stream",
        "Content-Disposition":
          res.headers.get("content-disposition") || 'attachment; filename="sast-feedback.jsonl"',
        "Cache-Control": "no-store",
      },
    });
  } catch (err) {
    return proxyFailure(err);
  }
}
