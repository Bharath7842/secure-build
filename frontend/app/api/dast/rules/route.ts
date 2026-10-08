import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function GET() {
  return dastProxy("/dast/rules");
}

export async function PATCH(request: NextRequest) {
  return dastProxy("/dast/rules", { method: "PATCH", body: await request.text() });
}
