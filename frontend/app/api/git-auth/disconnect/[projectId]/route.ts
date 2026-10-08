import { NextRequest, NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

type RouteParams = { params: Promise<{ projectId: string }> };

export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params;
  try {
    const res = await sastFetch(`/git-auth/${projectId}/disconnect`, { method: "DELETE" });
    if (res.status === 204) {
      return new NextResponse(null, { status: 204 });
    }
    const body = await res.json();
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Failed to reach SAST API" },
      { status: 500 }
    );
  }
}
