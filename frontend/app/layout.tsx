import type { Metadata } from "next";
import Sidebar from "@/components/Sidebar";
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
        <Sidebar />
        <main className="h-screen min-w-0 flex-1 overflow-x-hidden overflow-y-auto">
          {children}
        </main>
      </body>
    </html>
  );
}
