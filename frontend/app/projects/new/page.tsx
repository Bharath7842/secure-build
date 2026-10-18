"use client";

import { useRouter } from "next/navigation";
import { Suspense, useState } from "react";

import PageContainer from "@/components/PageContainer";
import ProjectForm from "@/components/ProjectForm";
import { useActiveProject } from "@/components/project/ActiveProjectProvider";
import { api } from "@/lib/api";
import type { ProjectCreateInput } from "@/lib/types";

export default function NewProjectPage() {
  const router = useRouter();
  const { refresh, setActiveProjectId } = useActiveProject();
  // Bumped after a successful create so the form remounts empty if the browser
  // restores this page (Back) instead of rebuilding it.
  const [formKey, setFormKey] = useState(0);

  async function handleSubmit(input: ProjectCreateInput) {
    const project = await api.projects.create(input);
    // The new project becomes the one the scan menus are about.
    await refresh();
    setActiveProjectId(project.id);
    setFormKey((key) => key + 1);
    router.push("/projects?created=1");
  }

  return (
    <PageContainer>
      <div className="max-w-3xl">
        <h1 className="font-display text-3xl text-[var(--ink)]">Create New Project</h1>
        <div className="mt-8">
          {/* ProjectForm reads useSearchParams() for the "Connect GitHub"/
              "Connect GitLab" redirect back from app/git-auth/[provider]/callback —
              this page is fully static, so that read needs a Suspense boundary. */}
          <Suspense fallback={null}>
            <ProjectForm key={formKey} mode="create" onSubmit={handleSubmit} />
          </Suspense>
        </div>
      </div>
    </PageContainer>
  );
}
