"use client";

import NetraInbox from "@/components/agent-reports/NetraInbox";
import PageContainer from "@/components/PageContainer";

export default function AgentReportsPage() {
  return (
    <PageContainer>
      <div>
        <h1 className="font-display text-3xl text-[var(--ink)]">Netra inbox</h1>
        <p className="mt-2 text-sm text-[var(--muted)]">
          Claude Code or Codex pushes a short summary and an ordered fix list here on a schedule. Netra
          shows that list as it arrived — not the full vulnerability report.
        </p>
      </div>
      <div className="mt-8">
        <NetraInbox />
      </div>
    </PageContainer>
  );
}
