import { dastProxy } from "@/lib/server-dast";

export const dynamic = "force-dynamic";

export async function GET() {
  return dastProxy("/setup/status");
}
