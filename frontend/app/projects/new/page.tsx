"use client";

import { useRouter } from "next/navigation";
import { Suspense } from "react";

import PageContainer from "@/components/PageContainer";
import ProjectForm from "@/components/ProjectForm";
import { api } from "@/lib/api";
import type { ProjectCreateInput } from "@/lib/types";

export default function NewProjectPage() {
  const router = useRouter();

  async function handleSubmit(input: ProjectCreateInput) {
    const project = await api.projects.create(input);
    router.push(`/projects/${project.id}`);
  }

  return (
    <PageContainer>
      <div className="max-w-3xl">
        <h1 className="font-display text-3xl text-[var(--ink)]">New Project</h1>
        <p className="mt-2 text-sm text-[var(--muted)]">
          Configure the repository, scan defaults, and compliance settings for a new project.
        </p>
        <div className="mt-8">
          {/* ProjectForm reads useSearchParams() for the "Connect GitHub"/
              "Connect GitLab" redirect back from app/git-auth/[provider]/callback —
              this page is fully static, so that read needs a Suspense boundary. */}
          <Suspense fallback={null}>
            <ProjectForm mode="create" onSubmit={handleSubmit} />
          </Suspense>
        </div>
      </div>
    </PageContainer>
  );
}
