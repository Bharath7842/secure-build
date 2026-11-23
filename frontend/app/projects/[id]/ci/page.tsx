"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import GitlabCiGuide from "@/components/ci/GitlabCiGuide";
import PageContainer from "@/components/PageContainer";
import { ApiError, api } from "@/lib/api";
import type { ProjectCiSetup } from "@/lib/types";

export default function ProjectGitlabCiPage() {
  const { id } = useParams<{ id: string }>();
  const [setup, setSetup] = useState<ProjectCiSetup | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.projects
      .ciSetup(id)
      .then((s) => active && setSetup(s))
      .catch((err) => active && setError(err instanceof ApiError ? err.message : "Failed to load project."));
    return () => {
      active = false;
    };
  }, [id]);

  return (
    <PageContainer>
      <div className="max-w-5xl">
        <Link href="/projects" className="text-sm font-medium text-[var(--muted)] hover:text-[var(--accent)]">
          ← Projects
        </Link>
        <h1 className="mt-3 font-display text-3xl text-[var(--ink)]">GitLab CI integration</h1>
        {setup && (
          <p className="mt-1 text-sm text-[var(--muted)]">
            Scan <span className="font-medium text-[var(--ink)]">{setup.project_name}</span> from your GitLab pipeline in two steps.
          </p>
        )}

        {error ? (
          <div className="mt-6 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>
        ) : !setup ? (
          <p className="mt-6 text-sm text-[var(--muted)]">Loading…</p>
        ) : (
          <div className="mt-8">
            <GitlabCiGuide setup={setup} />
          </div>
        )}
      </div>
    </PageContainer>
  );
}
