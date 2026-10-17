import type { Metadata } from "next";
import AppShell from "@/components/AppShell";
import { AuthProvider } from "@/components/auth/AuthProvider";
import Forbidden from "@/components/Forbidden";
import { sessionForRequest } from "@/lib/server-session";
import "./globals.css";

export const metadata: Metadata = {
  title: "Secure Build",
  description: "Secure Build — automated security scanning for your projects.",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // Redirects to sign-in when a protected page has no valid session; the
  // page itself is replaced by <Forbidden/> when the user may not see it.
  const { me, forbidden } = await sessionForRequest();
  return (
    <html lang="en" className="h-full overflow-hidden">
      <body className="flex h-screen min-w-0 overflow-hidden antialiased">
        <AuthProvider me={me}>
          <AppShell>{forbidden && me ? <Forbidden landing={me.landing} /> : children}</AppShell>
        </AuthProvider>
      </body>
    </html>
  );
}
