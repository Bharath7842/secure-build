import { NextRequest, NextResponse } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  try {
    const search = request.nextUrl.search;
    const res = await sastFetch(`/scans/${id}/logs${search}`);
    const body = await res.json();
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return proxyFailure(err);
  }
}
