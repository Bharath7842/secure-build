"use client";

import type { ScanReport } from "@/lib/types";

import AgentArtifactCard from "@/components/AgentArtifactCard";

interface ScanFindingsCardProps {
  report: ScanReport;
  onOpen: () => void;
  active?: boolean;
}

function FindingsIcon() {
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
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12h6M12 9v6" />
    </svg>
  );
}

export default function ScanFindingsCard({ onOpen, active = false }: ScanFindingsCardProps) {
  return (
    <AgentArtifactCard
      icon={<FindingsIcon />}
      tone="blue"
      title="Findings"
      subtitle=""
      active={active}
      onClick={onOpen}
      ariaLabel="Open findings"
    />
  );
}
