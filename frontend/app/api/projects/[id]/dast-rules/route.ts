import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function GET(_request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return dastProxy(`/projects/${encodeURIComponent(id)}/dast-rules`);
}

export async function PATCH(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return dastProxy(`/projects/${encodeURIComponent(id)}/dast-rules`, { method: "PATCH", body: await request.text() });
}

export async function DELETE(_request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return dastProxy(`/projects/${encodeURIComponent(id)}/dast-rules`, { method: "DELETE" });
}
