import { NextRequest, NextResponse } from "next/server";

import { dastProxy } from "@/lib/server-dast";

const ACTIONS = new Set(["approve", "mark-processed"]);

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ action: string }> }
) {
  const { action } = await params;
  if (!ACTIONS.has(action)) {
    return NextResponse.json({ detail: "Unsupported learning action" }, { status: 400 });
  }
  return dastProxy(`/feedback/learning/${action}`, { method: "POST", body: await request.text() });
}
