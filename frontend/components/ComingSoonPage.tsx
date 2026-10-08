import type { ReactNode } from "react";

import PageContainer from "@/components/PageContainer";

/**
 * Shared placeholder for a sidebar section that doesn't have a real page
 * behind it yet (mirrors the pattern already used for the DAST mockup —
 * a nav entry with no backend, filled in incrementally later).
 */
export default function ComingSoonPage({
  title,
  description,
  note,
}: {
  title: string;
  description: string;
  note?: ReactNode;
}) {
  return (
    <PageContainer>
      <div>
        <h1 className="font-display text-3xl text-[var(--ink)]">{title}</h1>
        <p className="mt-2 max-w-2xl text-[var(--muted)]">{description}</p>
      </div>

      <div className="mt-8 rounded-lg border border-dashed border-slate-300 bg-white/60 px-8 py-16 text-center">
        <p className="text-sm font-semibold uppercase tracking-wide text-slate-400">Coming soon</p>
        <p className="mt-2 text-[var(--muted)]">This module isn&apos;t wired up yet — check back soon.</p>
      </div>

      {note && <div className="mt-6">{note}</div>}
    </PageContainer>
  );
}
