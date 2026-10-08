"use client";

import type { UsageSummary } from "@/lib/types";
import { usageCardSubtitle } from "@/lib/formatUsage";

import AgentArtifactCard from "@/components/AgentArtifactCard";

interface ScanUsageCardProps {
  usage: UsageSummary;
  onOpen: () => void;
  active?: boolean;
}

function UsageIcon() {
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
      <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

export default function ScanUsageCard({ usage, onOpen, active = false }: ScanUsageCardProps) {
  return (
    <AgentArtifactCard
      icon={<UsageIcon />}
      tone="blue"
      title="Token usage"
      subtitle={usageCardSubtitle(usage)}
      active={active}
      onClick={onOpen}
      ariaLabel="Open token usage"
    />
  );
}
