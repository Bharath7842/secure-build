import { NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const res = await sastFetch("/scan-limitations");
    const body = await res.json();
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Failed to reach SAST API" },
      { status: 500 }
    );
  }
}
