"use client";

import { useRouter } from "next/navigation";

import DastScanForm from "@/components/DastScanForm";
import ScanForm from "@/components/ScanForm";
import { api } from "@/lib/api";
import type { ScanCreateInput } from "@/lib/types";

interface NewScanFormProps {
  projectId?: string;
  scanType?: "sast" | "sca" | "sbom" | "dast";
}

export default function NewScanForm({ projectId, scanType = "sast" }: NewScanFormProps) {
  const router = useRouter();

  async function handleSubmit(input: ScanCreateInput) {
    const trigger = await api.scans.create(input);
    const suffix = trigger.reused ? "?reused=1" : "";
    // Same detail page for both scan types — frontend/app/scans/[id]/page.tsx
    // branches on scan_type internally.
    router.push(`/scans/${trigger.scan_id}${suffix}`);
  }

  if (scanType === "dast") {
    return <DastScanForm projectId={projectId} onSubmit={handleSubmit} />;
  }
  return <ScanForm projectId={projectId} scanType={scanType} onSubmit={handleSubmit} />;
}
