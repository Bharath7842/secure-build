import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function POST() {
  return dastProxy("/auth/sessions/revoke-others", { method: "POST" });
}
