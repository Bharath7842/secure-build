"use client";

import { usePathname } from "next/navigation";

import Sidebar from "@/components/Sidebar";

/** Routes that render on their own, without the dashboard sidebar. */
const STANDALONE_ROUTES = ["/login"];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const standalone = STANDALONE_ROUTES.some((r) => pathname === r || pathname.startsWith(`${r}/`));

  if (standalone) {
    return <div className="h-screen min-w-0 flex-1 overflow-x-hidden overflow-y-auto">{children}</div>;
  }

  return (
    <>
      <Sidebar />
      <main className="h-screen min-w-0 flex-1 overflow-x-hidden overflow-y-auto">{children}</main>
    </>
  );
}
