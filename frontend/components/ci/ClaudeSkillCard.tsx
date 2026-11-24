"use client";

import { useState } from "react";

import CopyButton from "@/components/ci/CopyButton";
import type { ProjectCiSetup } from "@/lib/types";

function Command({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2">
      <pre className="min-w-0 flex-1 overflow-x-auto rounded-md border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-[12.5px] leading-[1.6] text-[var(--ink)]">
        <code>{text}</code>
      </pre>
      <CopyButton text={text} label="Copy" />
    </div>
  );
}

/** Download the project's `secure-fix` Claude Code skill and say how to use it. */
export default function ClaudeSkillCard({ setup, exampleId }: { setup: ProjectCiSetup; exampleId?: string | null }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function download() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/projects/${setup.project_id}/claude-skill`);
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.detail ?? `Download failed (${res.status})`);
      }
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = "SKILL.md";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed");
    } finally {
      setBusy(false);
    }
  }

  const sample = exampleId || "SB-7F3A9C21";
  const direct = setup.api_url
    ? `mkdir -p .claude/skills/secure-fix && curl -sS -H "Authorization: Bearer $SAST_API_TOKEN" "${setup.api_url}/projects/${setup.project_id}/claude-skill" -o .claude/skills/secure-fix/SKILL.md`
    : null;

  return (
    <section>
      <h2 className="font-display text-xl text-[var(--ink)]">Fix issues with Claude Code</h2>
      <p className="mt-1 text-sm text-[var(--muted)]">
        Every issue has a short ID such as <span className="font-mono text-[var(--ink)]">SB-7F3A9C21</span>, shown on each finding. It stays the same across
        rescans. Give an ID to Claude Code and the skill below looks the issue up in Secure Build, then either writes a fix plan for you to approve
        (<span className="font-mono">plan</span>) or fixes it, runs the tests and pushes a branch (<span className="font-mono">agent</span>).
      </p>

      <ol className="mt-5 space-y-5 text-sm text-[var(--ink)]">
        <li>
          <p className="font-medium">1. Download the skill for {setup.project_name}</p>
          <p className="mt-1 text-[var(--muted)]">
            It already has this project&apos;s ID{setup.api_url ? " and API address" : ""}. It never contains the token.
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={download}
              disabled={busy}
              aria-busy={busy}
              className="inline-flex items-center gap-1.5 rounded-md bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-wait disabled:opacity-60"
            >
              {busy ? "Preparing…" : "Download SKILL.md"}
            </button>
            {error && (
              <span role="alert" className="text-sm text-red-700">
                {error}
              </span>
            )}
          </div>
          <p className="mt-3 text-[var(--muted)]">Save it in your repository as:</p>
          <div className="mt-1">
            <Command text=".claude/skills/secure-fix/SKILL.md" />
          </div>
          {direct && (
            <>
              <p className="mt-3 text-[var(--muted)]">Or fetch it straight into the repository (needs the token from step 2):</p>
              <div className="mt-1">
                <Command text={direct} />
              </div>
            </>
          )}
        </li>

        <li>
          <p className="font-medium">2. Give Claude Code the token</p>
          <p className="mt-1 text-[var(--muted)]">
            Use the same <span className="font-mono">SAST_API_TOKEN</span> as the pipeline, as an environment variable in the terminal where you start Claude Code.
            Keep it out of files and commits.
          </p>
          <div className="mt-2">
            <Command text={`export SAST_API_TOKEN="<token>"`} />
          </div>
        </li>

        <li>
          <p className="font-medium">3. Ask for an issue</p>
          <p className="mt-1 text-[var(--muted)]">Start Claude Code in the repository, then:</p>
          <div className="mt-2 space-y-2">
            <Command text="/secure-fix list" />
            <Command text={`/secure-fix ${sample} plan`} />
            <Command text={`/secure-fix ${sample} agent use a parameterized query`} />
          </div>
          <p className="mt-2 text-[var(--muted)]">
            <span className="font-mono">list</span> shows the priority issues. <span className="font-mono">plan</span> stops for your approval before
            changing code. <span className="font-mono">agent</span> goes ahead on its own and pushes a <span className="font-mono">secure-fix/…</span>{" "}
            branch, never the default branch. Add your own fix plan after the mode and Claude follows it. Leave the mode out and Claude asks.
          </p>
        </li>
      </ol>
    </section>
  );
}
