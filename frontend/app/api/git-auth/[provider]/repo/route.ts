import { NextRequest, NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

type RouteParams = { params: Promise<{ provider: string }> };

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { provider } = await params;
  const query = new URLSearchParams();
  for (const key of ["url", "connection_id", "project_id"]) {
    const value = request.nextUrl.searchParams.get(key);
    if (value) query.set(key, value);
  }

  try {
    const res = await sastFetch(`/git-auth/${provider}/repo?${query.toString()}`);
    const body = await res.json();
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Failed to reach SAST API" },
      { status: 500 }
    );
  }
}
