import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function GET() {
  return dastProxy("/dast/model-routing");
}

export async function PUT(request: NextRequest) {
  return dastProxy("/dast/model-routing", { method: "PUT", body: await request.text() });
}
