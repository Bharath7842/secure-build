import { NextRequest, NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

type RouteParams = { params: Promise<{ provider: string }> };

export async function POST(request: NextRequest, { params }: RouteParams) {
  const { provider } = await params;
  try {
    const payload = await request.json();
    const res = await sastFetch(`/git-auth/${provider}/token`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Failed to reach SAST API" },
      { status: 500 }
    );
  }
}
