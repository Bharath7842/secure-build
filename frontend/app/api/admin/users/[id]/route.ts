import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

type Params = { params: Promise<{ id: string }> };

export async function GET(_request: NextRequest, { params }: Params) {
  const { id } = await params;
  return dastProxy(`/admin/users/${encodeURIComponent(id)}`);
}

export async function PATCH(request: NextRequest, { params }: Params) {
  const { id } = await params;
  return dastProxy(`/admin/users/${encodeURIComponent(id)}`, { method: "PATCH", body: await request.text() });
}
