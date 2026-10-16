import type { Metadata } from "next";
import AppShell from "@/components/AppShell";
import "./globals.css";

export const metadata: Metadata = {
  title: "Secure Build",
  description: "Secure Build — automated security scanning for your projects.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full overflow-hidden">
      <body className="flex h-screen min-w-0 overflow-hidden antialiased">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
