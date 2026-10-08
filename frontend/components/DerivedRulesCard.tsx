"use client";

import AgentArtifactCard from "@/components/AgentArtifactCard";
import type { DerivedRule, DerivedRulesSummary } from "@/lib/types";

interface DerivedRulesCardProps {
  rules: DerivedRule[];
  summary?: DerivedRulesSummary;
  onOpen: () => void;
  active?: boolean;
}

function RulesIcon() {
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
      <path d="M4 7V4h16v3M9 20h6M12 4v16" />
    </svg>
  );
}

export default function DerivedRulesCard({ rules, summary, onOpen, active = false }: DerivedRulesCardProps) {
  const llmCount = rules.filter((r) => r.id.startsWith("runtime-llm-")).length;
  const subtitle =
    (llmCount > 0
      ? `${rules.length} rule(s) · ${llmCount} from LLM`
      : `${rules.length} rule(s) from call-graph wrappers`) +
    (summary?.failed ? ` · ${summary.failed} failed` : "");

  return (
    <AgentArtifactCard
      icon={<RulesIcon />}
      tone="purple"
      title="Derived rules"
      subtitle={subtitle}
      active={active}
      onClick={onOpen}
      ariaLabel="Open derived regex rules"
    />
  );
}
