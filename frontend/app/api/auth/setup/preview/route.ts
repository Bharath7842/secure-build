import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

/** Whose account an invite or reset link is for. Doesn't use the link up. */
export async function POST(request: NextRequest) {
  return dastProxy("/auth/setup/preview", { method: "POST", body: await request.text() });
}
