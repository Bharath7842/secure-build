import { NextRequest, NextResponse } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

export async function GET(request: NextRequest) {
  try {
    const res = await sastFetch(`/agent-reports${request.nextUrl.search}`);
    const body = await res.json();
    return NextResponse.json(body, { status: res.status, headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    return proxyFailure(err);
  }
}
