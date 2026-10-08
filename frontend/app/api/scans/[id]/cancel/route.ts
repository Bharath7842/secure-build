import { NextRequest, NextResponse } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

export async function POST(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  try {
    const res = await sastFetch(`/scans/${id}/cancel`, { method: "POST" });
    const body = await res.json().catch(() => ({ detail: "Cancel failed" }));
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return proxyFailure(err);
  }
}
