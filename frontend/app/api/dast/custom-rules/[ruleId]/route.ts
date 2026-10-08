import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function GET(_request: NextRequest, { params }: { params: Promise<{ ruleId: string }> }) {
  const { ruleId } = await params;
  return dastProxy(`/dast/custom-rules/${encodeURIComponent(ruleId)}`);
}

export async function PUT(request: NextRequest, { params }: { params: Promise<{ ruleId: string }> }) {
  const { ruleId } = await params;
  return dastProxy(`/dast/custom-rules/${encodeURIComponent(ruleId)}`, { method: "PUT", body: await request.text() });
}

export async function DELETE(_request: NextRequest, { params }: { params: Promise<{ ruleId: string }> }) {
  const { ruleId } = await params;
  return dastProxy(`/dast/custom-rules/${encodeURIComponent(ruleId)}`, { method: "DELETE" });
}
