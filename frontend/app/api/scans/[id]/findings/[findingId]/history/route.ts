import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

type RouteParams = { params: Promise<{ id: string; findingId: string }> };

export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { id, findingId } = await params;
  return dastProxy(
    `/scans/${encodeURIComponent(id)}/findings/${encodeURIComponent(findingId)}/history`,
  );
}
