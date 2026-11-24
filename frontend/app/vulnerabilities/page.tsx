"use client";

import Link from "next/link";

import PageContainer from "@/components/PageContainer";
import { useActiveProject } from "@/components/project/ActiveProjectProvider";
import VulnerabilityReport from "@/components/vulnerability/VulnerabilityReport";

export default function VulnerabilityReportPage() {
  const { activeProject, loading } = useActiveProject();

  return (
    <PageContainer>
      <div>
        <h1 className="font-display text-3xl text-[var(--ink)]">Vulnerability report</h1>
        {activeProject && <p className="mt-1 text-sm font-medium text-[var(--ink)]">Project: {activeProject.name}</p>}
        <p className="mt-2 text-sm text-[var(--muted)]">
          Every issue found by SAST, SCA, SBOM and DAST scans of this project, followed from scan to scan: what is
          still open, what was fixed, and how fast.
        </p>
      </div>

      <div className="mt-8">
        {!loading && !activeProject ? (
          <div className="rounded-md border border-dashed border-slate-300 bg-white/60 px-6 py-10 text-center">
            <p className="text-sm text-[var(--muted)]">
              Select a project in the sidebar to see its vulnerability report.{" "}
              <Link href="/projects" className="font-medium text-[var(--accent)] hover:underline">
                Choose a project
              </Link>
            </p>
          </div>
        ) : activeProject ? (
          <VulnerabilityReport key={activeProject.id} projectId={activeProject.id} />
        ) : null}
      </div>
    </PageContainer>
  );
}
