import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function POST(_request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return dastProxy(`/admin/users/${encodeURIComponent(id)}/invite-link`, { method: "POST" });
}
