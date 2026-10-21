import { NextRequest, NextResponse } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  try {
    const res = await sastFetch(
      `/scans/${encodeURIComponent(id)}/decision-diff.xlsx${request.nextUrl.search}`,
    );
    if (!res.ok) {
      const body = await res.json().catch(() => ({ detail: "Export failed" }));
      return NextResponse.json(body, { status: res.status });
    }
    return new NextResponse(await res.arrayBuffer(), {
      status: 200,
      headers: {
        "Content-Type":
          res.headers.get("content-type") ||
          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "Content-Disposition":
          res.headers.get("content-disposition") || 'attachment; filename="decision-diff.xlsx"',
        "Cache-Control": "no-store",
      },
    });
  } catch (err) {
    return proxyFailure(err);
  }
}
