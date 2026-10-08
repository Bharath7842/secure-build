import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function GET() {
  return dastProxy("/dast/settings");
}

export async function PATCH(request: NextRequest) {
  return dastProxy("/dast/settings", { method: "PATCH", body: await request.text() });
}
