import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

type RouteParams = { params: Promise<{ id: string; findingId: string }> };

function reviewPath({ id, findingId }: { id: string; findingId: string }) {
  return `/scans/${encodeURIComponent(id)}/findings/${encodeURIComponent(findingId)}/review`;
}

export async function GET(_request: NextRequest, { params }: RouteParams) {
  return dastProxy(reviewPath(await params));
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  return dastProxy(reviewPath(await params), { method: "POST", body: await request.text() });
}
