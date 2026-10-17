import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  return dastProxy(`/admin/users${request.nextUrl.search}`);
}

export async function POST(request: NextRequest) {
  return dastProxy("/admin/users", { method: "POST", body: await request.text() });
}
