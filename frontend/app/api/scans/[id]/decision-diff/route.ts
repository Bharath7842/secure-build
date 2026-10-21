import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return dastProxy(`/scans/${encodeURIComponent(id)}/decision-diff${request.nextUrl.search}`);
}
