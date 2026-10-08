import { NextRequest, NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

type RouteParams = { params: Promise<{ id: string }> };

export async function PATCH(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  try {
    const payload = await request.json();
    const res = await sastFetch(`/projects/${id}/limitations`, {
      method: "PATCH",
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
