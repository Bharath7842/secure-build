import type { Metadata } from "next";

import BrandMark from "@/components/login/BrandMark";
import BrandPanel from "@/components/login/BrandPanel";
import LoginForm from "@/components/login/LoginForm";

export const metadata: Metadata = {
  title: "Sign in · Secure Build",
  description: "Sign in to your Secure Build workspace.",
};

export default function LoginPage() {
  return (
    <div className="flex min-h-full flex-col lg:flex-row">
      {/* Compact brand header on small screens; full panel from lg up. */}
      <header className="bg-[var(--sidebar)] px-4 py-5 sm:px-8 lg:hidden">
        <BrandMark />
        <p className="mt-2 text-sm text-slate-300">Build confidently. Ship securely.</p>
      </header>

      <BrandPanel />

      <main className="flex flex-1 items-start justify-center px-4 py-10 sm:px-8 lg:items-center lg:py-12">
        <div className="w-full max-w-[25rem]">
          <h1 className="text-3xl font-semibold tracking-tight text-[var(--ink)]">Welcome back</h1>
          <p className="mt-2 text-base text-[var(--muted)]">Sign in to your Secure Build workspace.</p>
          <LoginForm />
        </div>
      </main>
    </div>
  );
}
