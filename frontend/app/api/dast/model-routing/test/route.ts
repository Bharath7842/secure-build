import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  return dastProxy("/dast/model-routing/test", { method: "POST", body: await request.text() });
}
