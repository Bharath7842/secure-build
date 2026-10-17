import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return dastProxy(`/admin/users/${encodeURIComponent(id)}/permissions`, {
    method: "PUT",
    body: await request.text(),
  });
}
