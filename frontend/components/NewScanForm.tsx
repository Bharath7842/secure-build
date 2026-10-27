"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";

import { useAuth } from "@/components/auth/AuthProvider";
import DastScanForm from "@/components/DastScanForm";
import { useActiveProject } from "@/components/project/ActiveProjectProvider";
import ScanForm from "@/components/ScanForm";
import { api } from "@/lib/api";
import type { Project, ScanCreateInput } from "@/lib/types";

interface NewScanFormProps {
  scanType?: "sast" | "sca" | "sbom" | "dast";
  /** DAST only: an earlier scan whose saved settings fill the form. */
  fromScanId?: string;
}

/** Why `project` can't run this scan type yet, or null. DAST needs no repository. */
function setupProblem(project: Project, scanType: NonNullable<NewScanFormProps["scanType"]>): string | null {
  if (scanType === "dast") return null;
  if (!project.default_git_url?.trim()) {
    return "This project has no repository yet. SAST, SCA and SBOM scan source code, so add a repository URL in the project settings.";
  }
  if (scanType === "sca" && !project.enable_sca) return "SCA is turned off for this project.";
  if (scanType === "sbom" && !project.enable_sbom) return "SBOM is turned off for this project.";
  return null;
}

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-dashed border-slate-300 bg-white/60 px-6 py-8 text-sm text-[var(--muted)]">
      {children}
    </div>
  );
}

export default function NewScanForm({ scanType = "sast", fromScanId }: NewScanFormProps) {
  const router = useRouter();
  const me = useAuth();
  const { activeProject, loading } = useActiveProject();

  async function handleSubmit(input: ScanCreateInput) {
    const trigger = await api.scans.create(input);
    const suffix = trigger.reused ? "?reused=1" : "";
    // Same detail page for both scan types — frontend/app/scans/[id]/page.tsx
    // branches on scan_type internally.
    router.push(`/scans/${trigger.scan_id}${suffix}`);
  }

  if (loading) return <p className="text-sm text-[var(--muted)]">Loading project…</p>;
  if (!activeProject) {
    return (
      <Notice>
        Select a project in the sidebar to start a scan.{" "}
        <Link href="/projects" className="font-medium text-[var(--accent)] hover:underline">
          Choose a project
        </Link>
        {me?.pages.includes("page.project_new") && (
          <>
            {" "}or{" "}
            <Link href="/projects/new" className="font-medium text-[var(--accent)] hover:underline">
              create one
            </Link>
          </>
        )}
        .
      </Notice>
    );
  }

  const problem = setupProblem(activeProject, scanType);
  if (problem) {
    return (
      <Notice>
        {problem}{" "}
        {me?.permissions.includes("projects.manage") && (
          <Link
            href={`/projects/${activeProject.id}`}
            className="font-medium text-[var(--accent)] hover:underline"
          >
            Open project
          </Link>
        )}
      </Notice>
    );
  }

  if (scanType === "dast") return <DastScanForm project={activeProject} onSubmit={handleSubmit} fromScanId={fromScanId} />;
  return <ScanForm project={activeProject} scanType={scanType} onSubmit={handleSubmit} />;
}
