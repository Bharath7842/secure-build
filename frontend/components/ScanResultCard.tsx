"use client";

import type { ScanDiscovery } from "@/lib/types";

import AgentArtifactCard from "@/components/AgentArtifactCard";

interface ScanResultCardProps {
  discovery: ScanDiscovery;
  onOpen: () => void;
  active?: boolean;
}

function DiscoveryIcon() {
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
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.3-4.3" />
      <path d="M11 8v6M8 11h6" />
    </svg>
  );
}

export default function ScanResultCard({ discovery, onOpen, active = false }: ScanResultCardProps) {
  const fileCount = discovery.scan_summary.total_files;
  const critical = discovery.module_plan.risk_counts.CRITICAL ?? 0;

  return (
    <AgentArtifactCard
      icon={<DiscoveryIcon />}
      tone="emerald"
      title="Discovery results"
      subtitle={`${discovery.llm_analysis.tech_stack} · ${fileCount} files${
        critical > 0 ? ` · ${critical} critical` : ""
      }`}
      active={active}
      onClick={onOpen}
      ariaLabel="Open discovery results"
    />
  );
}
