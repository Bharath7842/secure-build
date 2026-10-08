"use client";

import AgentArtifactCard from "@/components/AgentArtifactCard";
import type { AstSummary } from "@/lib/types";

interface AstSummaryCardProps {
  summary: AstSummary;
  onOpen: () => void;
  active?: boolean;
}

function AstIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M16 18l6-6-6-6M8 6l-6 6 6 6" />
    </svg>
  );
}

export default function AstSummaryCard({ summary, onOpen, active = false }: AstSummaryCardProps) {
  const stacks = Object.values(summary.stacks ?? {});
  const entryPointCount = stacks.reduce((sum, s) => sum + (s.entry_point_count ?? 0), 0);
  const routeCount = stacks.reduce((sum, s) => sum + (s.route_count ?? 0), 0);

  const parts: string[] = [];
  if (entryPointCount > 0) parts.push(`${entryPointCount} entry points`);
  if (routeCount > 0) parts.push(`${routeCount} routes`);
  const subtitle = parts.length > 0 ? parts.join(" · ") : "Annotation & decorator structure";

  return (
    <AgentArtifactCard
      icon={<AstIcon />}
      tone="blue"
      title="AST structure"
      subtitle={subtitle}
      active={active}
      onClick={onOpen}
      ariaLabel="Open AST structure"
    />
  );
}
