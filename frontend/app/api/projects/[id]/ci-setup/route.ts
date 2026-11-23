import { NextRequest, NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

type RouteParams = { params: Promise<{ id: string }> };

// The response can carry the backend CI token (admins only): never cache it.
export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  try {
    const res = await sastFetch(`/projects/${id}/ci-setup`);
    const body = await res.json();
    return NextResponse.json(body, { status: res.status, headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Failed to reach SAST API" },
      { status: 500 }
    );
  }
}
