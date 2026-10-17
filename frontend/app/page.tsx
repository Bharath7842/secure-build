import { redirect } from "next/navigation";

import { getSession } from "@/lib/server-session";

export default async function Home() {
  const me = await getSession();
  redirect(me ? me.landing : "/login");
}
