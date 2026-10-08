import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function GET() {
  return dastProxy("/dast/custom-rules");
}

export async function POST(request: NextRequest) {
  return dastProxy("/dast/custom-rules", { method: "POST", body: await request.text() });
}
