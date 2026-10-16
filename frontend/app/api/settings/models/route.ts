import { NextRequest, NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

export const dynamic = "force-dynamic";

function failure(err: unknown) {
  return NextResponse.json(
    { detail: err instanceof Error ? err.message : "Failed to reach SAST API" },
    { status: 500 }
  );
}

export async function GET() {
  try {
    const res = await sastFetch("/settings/models");
    return NextResponse.json(await res.json(), { status: res.status });
  } catch (err) {
    return failure(err);
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const payload = await request.json();
    const res = await sastFetch("/settings/models", {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    return NextResponse.json(await res.json(), { status: res.status });
  } catch (err) {
    return failure(err);
  }
}
