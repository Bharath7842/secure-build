import { NextRequest, NextResponse } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

export async function GET(_request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  try {
    const res = await sastFetch(`/agent-reports/${encodeURIComponent(id)}`);
    const body = await res.json();
    return NextResponse.json(body, { status: res.status, headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    return proxyFailure(err);
  }
}
