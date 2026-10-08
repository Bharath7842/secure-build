import { NextRequest, NextResponse } from "next/server";

import { sastFetch } from "@/lib/server-sast";

export async function GET() {
  try {
    const res = await sastFetch("/projects");
    const body = await res.json();
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      { detail: err instanceof Error ? err.message : "Failed to reach SAST API" },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const payload = await request.json();
    const res = await sastFetch("/projects", {
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
