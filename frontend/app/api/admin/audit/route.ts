import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  return dastProxy(`/admin/audit${request.nextUrl.search}`);
}
