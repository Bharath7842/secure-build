import { NextRequest, NextResponse } from "next/server";

import { proxyFailure } from "@/lib/server-dast";
import { sastFetch } from "@/lib/server-sast";

export async function GET(request: NextRequest) {
  try {
    const search = request.nextUrl.search;
    const res = await sastFetch(`/scans${search}`);
    const body = await res.json();
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return proxyFailure(err);
  }
}

export async function POST(request: NextRequest) {
  try {
    const payload = await request.json();
    const res = await sastFetch("/scans", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return proxyFailure(err);
  }
}
