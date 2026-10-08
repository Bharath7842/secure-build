import { NextRequest, NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

type RouteParams = { params: Promise<{ provider: string }> };

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { provider } = await params;
  const projectId = request.nextUrl.searchParams.get("project_id");
  const query = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
  try {
    const res = await sastFetch(`/git-auth/${provider}/authorize${query}`);
    const body = await res.json();
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Failed to reach SAST API" },
      { status: 500 }
    );
  }
}
