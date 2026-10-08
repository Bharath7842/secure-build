import { NextRequest, NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

type RouteParams = { params: Promise<{ provider: string }> };

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { provider } = await params;
  const connectionId = request.nextUrl.searchParams.get("connection_id");
  const projectId = request.nextUrl.searchParams.get("project_id");
  const query = new URLSearchParams();
  if (connectionId) query.set("connection_id", connectionId);
  if (projectId) query.set("project_id", projectId);

  try {
    const res = await sastFetch(`/git-auth/${provider}/repos?${query.toString()}`);
    const body = await res.json();
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Failed to reach SAST API" },
      { status: 500 }
    );
  }
}
