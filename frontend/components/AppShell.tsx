"use client";

import { usePathname } from "next/navigation";

import { useAuth } from "@/components/auth/AuthProvider";
import Forbidden from "@/components/Forbidden";
import Sidebar from "@/components/Sidebar";
import { isPublicPage, pageKeyFor } from "@/lib/access";

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const me = useAuth();

  // The sign-in and setup pages render on their own, without the sidebar.
  if (isPublicPage(pathname)) {
    return <div className="h-screen min-w-0 flex-1 overflow-x-hidden overflow-y-auto">{children}</div>;
  }

  // The root layout refuses a page on a full load; this covers client-side
  // navigation, where the root layout doesn't run again.
  const key = pageKeyFor(pathname);
  const forbidden = !!me && !!key && !me.pages.includes(key);

  return (
    <>
      <Sidebar />
      <main className="h-screen min-w-0 flex-1 overflow-x-hidden overflow-y-auto">
        {forbidden ? <Forbidden landing={me.landing} /> : children}
      </main>
    </>
  );
}
