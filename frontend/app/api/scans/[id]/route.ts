import { NextRequest, NextResponse } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  try {
    const res = await sastFetch(`/scans/${id}`, { method: "DELETE" });
    if (res.status === 204) {
      return new NextResponse(null, { status: 204 });
    }
    const body = await res.json().catch(() => ({ detail: "Delete failed" }));
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return proxyFailure(err);
  }
}
