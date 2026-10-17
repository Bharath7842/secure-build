import { NextRequest } from "next/server";

import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

/** Accept an invite or reset link: set a password with its one-time token. */
export async function POST(request: NextRequest) {
  return dastProxy("/auth/setup", { method: "POST", body: await request.text() });
}
