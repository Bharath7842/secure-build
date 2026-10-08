"use client";

import Link from "next/link";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";

import PageContainer from "@/components/PageContainer";
import { ApiError, api } from "@/lib/api";

const PROVIDER_LABELS: Record<string, string> = {
  github: "GitHub",
  gitlab: "GitLab",
};

export default function GitAuthCallbackPage() {
  const params = useParams<{ provider: string }>();
  const provider = params.provider === "gitlab" ? "gitlab" : "github";
  const providerLabel = PROVIDER_LABELS[provider] ?? provider;
  const searchParams = useSearchParams();
  const router = useRouter();

  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function run() {
      const code = searchParams.get("code");
      const state = searchParams.get("state");
      const providerError = searchParams.get("error_description") || searchParams.get("error");

      if (providerError) {
        if (active) setError(providerError);
        return;
      }
      if (!code || !state) {
        if (active) setError(`${providerLabel} did not return an authorization code.`);
        return;
      }

      try {
        const { project_id, connection_id } = await api.gitAuth.callback(provider, code, state);
        if (!active) return;
        if (project_id) {
          // Connected from an existing project's edit page.
          router.replace(`/projects/${project_id}?git_connected=${provider}`);
        } else if (connection_id) {
          // Connected from the new-project form, before the project exists —
          // hand the pending connection back so the form can submit it.
          router.replace(
            `/projects/new?git_connection_id=${encodeURIComponent(connection_id)}&git_provider=${provider}`
          );
        } else {
          setError(`${providerLabel} connection did not complete.`);
        }
      } catch (err) {
        if (active) {
          setError(err instanceof ApiError ? err.message : `Failed to connect ${providerLabel}.`);
        }
      }
    }

    run();
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <PageContainer>
      <div className="mx-auto mt-16 max-w-md text-center">
        {error ? (
          <>
            <h1 className="font-display text-2xl text-[var(--ink)]">Connection failed</h1>
            <p className="mt-3 text-sm text-red-600">{error}</p>
            <Link href="/projects" className="mt-6 inline-block text-sm font-medium text-[var(--accent)]">
              ← Back to projects
            </Link>
          </>
        ) : (
          <p className="text-sm text-[var(--muted)]">Connecting {providerLabel}…</p>
        )}
      </div>
    </PageContainer>
  );
}
