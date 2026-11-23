"use client";

import { useMemo, useState, type ReactNode } from "react";

import CopyButton from "@/components/ci/CopyButton";
import { buildGitlabCiYaml } from "@/lib/gitlabCiTemplate";
import type { ProjectCiSetup } from "@/lib/types";

function Path({ parts }: { parts: string[] }) {
  return (
    <ol className="flex flex-wrap items-center gap-1.5 text-sm">
      {parts.map((part, i) => (
        <li key={part} className="flex items-center gap-1.5">
          <span className="rounded-md border border-slate-200 bg-white px-2 py-0.5 font-medium text-[var(--ink)]">{part}</span>
          {i < parts.length - 1 && (
            <svg aria-hidden viewBox="0 0 16 16" className="h-3.5 w-3.5 text-slate-400" fill="none" stroke="currentColor" strokeWidth="1.75">
              <path d="M6 3.5L10.5 8 6 12.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          )}
        </li>
      ))}
    </ol>
  );
}

function Field({ label, value, display, action }: { label: string; value: string; display?: ReactNode; action?: ReactNode }) {
  return (
    <div>
      <p className="text-[11px] font-medium uppercase tracking-wide text-[var(--muted)]">{label}</p>
      <div className="mt-1 flex items-center gap-2">
        <div className="min-w-0 flex-1 truncate rounded-md border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-[13px] text-[var(--ink)]" title={value}>
          {display ?? value}
        </div>
        {action}
        <CopyButton text={value} label="Copy" />
      </div>
    </div>
  );
}

function VariableCard({ name, value, settings, missing }: { name: string; value: string | null; settings: string; missing?: ReactNode }) {
  const [shown, setShown] = useState(false);
  const secret = name === "SAST_API_TOKEN";
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <Field label="Key" value={name} />
      <div className="mt-3">
        {value ? (
          <Field
            label="Value"
            value={value}
            display={secret && !shown ? "•".repeat(Math.min(value.length, 32)) : value}
            action={
              secret ? (
                <button
                  type="button"
                  onClick={() => setShown((s) => !s)}
                  className="shrink-0 rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-[var(--ink)] transition hover:border-[var(--accent)] hover:text-[var(--accent)]"
                >
                  {shown ? "Hide" : "Show"}
                </button>
              ) : undefined
            }
          />
        ) : (
          <div>
            <p className="text-[11px] font-medium uppercase tracking-wide text-[var(--muted)]">Value</p>
            <div className="mt-1 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">{missing}</div>
          </div>
        )}
      </div>
      <p className="mt-3 text-xs text-[var(--muted)]">{settings}</p>
    </div>
  );
}

export default function GitlabCiGuide({ setup }: { setup: ProjectCiSetup }) {
  const yaml = useMemo(() => buildGitlabCiYaml({ scanTypes: setup.scan_types, webUrl: setup.web_url }), [setup]);
  const lines = useMemo(() => yaml.replace(/\n$/, "").split("\n"), [yaml]);

  function download() {
    const url = URL.createObjectURL(new Blob([yaml], { type: "text/yaml" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = ".gitlab-ci.yml";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-12">
      <section>
        <h2 className="font-display text-xl text-[var(--ink)]">1. Add these variables in GitLab</h2>
        <p className="mt-1 text-sm text-[var(--muted)]">
          In the GitLab repository <span className="font-mono text-[var(--ink)]">{setup.repo_url}</span>, go to:
        </p>
        <div className="mt-2">
          <Path parts={["Settings", "CI/CD", "Variables", "Add variable"]} />
        </div>
        <p className="mt-2 text-sm text-[var(--muted)]">Add each one below: copy the key, then the value. Leave Environment scope as <span className="font-mono">All (default)</span>.</p>

        <div className="mt-5 grid gap-4 lg:grid-cols-3">
          <VariableCard
            name="SAST_API_URL"
            value={setup.api_url}
            settings={`Visibility: Visible.${setup.api_url_source === "ngrok" ? " Taken from your running ngrok tunnel; it changes when ngrok restarts." : ""}`}
            missing={
              <>
                No public backend URL found. Run <span className="font-mono">ngrok http 8000</span> or set{" "}
                <span className="font-mono">PUBLIC_API_URL</span> in the backend <span className="font-mono">.env</span>, then{" "}
                <button type="button" onClick={() => window.location.reload()} className="font-medium underline">
                  reload
                </button>
                .
              </>
            }
          />
          <VariableCard
            name="SAST_API_TOKEN"
            value={setup.token}
            settings="Visibility: Masked. Leave “Protect variable” unticked so every branch can use it."
            missing="Only an admin can see this token. Ask your Secure Build admin to add it."
          />
          <VariableCard name="SAST_PROJECT_ID" value={setup.project_id} settings="Visibility: Visible." />
        </div>
      </section>

      <section>
        <h2 className="font-display text-xl text-[var(--ink)]">2. Add the .gitlab-ci.yml file</h2>
        <p className="mt-1 text-sm text-[var(--muted)]">Copy this file into the root of the same repository and commit it:</p>
        <div className="mt-2">
          <Path parts={["Build", "Pipeline editor", "Paste", "Commit changes"]} />
        </div>
        <p className="mt-2 text-sm text-[var(--muted)]">
          Already have a <span className="font-mono">.gitlab-ci.yml</span>? Paste these jobs at the end of it, and make sure <span className="font-mono">test</span> is in its{" "}
          <span className="font-mono">stages</span>.
        </p>

        <div className="mt-5 overflow-hidden rounded-xl border border-slate-800 bg-slate-950 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 px-4 py-2.5">
            <span className="font-mono text-xs text-slate-300">
              .gitlab-ci.yml <span className="text-slate-500">· {setup.scan_types.map((t) => t.toUpperCase()).join(", ")} scan</span>
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={download}
                className="inline-flex items-center gap-1.5 rounded-md border border-white/15 bg-white/10 px-2.5 py-1 text-xs font-medium text-slate-100 transition hover:bg-white/20"
              >
                Download
              </button>
              <CopyButton text={yaml} label="Copy YAML" variant="primary" />
            </div>
          </div>
          <pre className="max-h-[36rem] overflow-auto py-3 font-mono text-[12.5px] leading-[1.6]">
            <code>
              {lines.map((line, i) => (
                <div key={i} className="flex">
                  <span aria-hidden className="w-12 shrink-0 select-none pr-4 text-right text-slate-600">
                    {i + 1}
                  </span>
                  <span className={`whitespace-pre pr-4 ${/^\s*#/.test(line) ? "text-slate-500" : /^[.\w-]+:/.test(line) ? "text-sky-300" : "text-slate-200"}`}>
                    {line || " "}
                  </span>
                </div>
              ))}
            </code>
          </pre>
        </div>
        <p className="mt-3 text-sm text-[var(--muted)]">
          Every push to a branch now starts a Secure Build scan. The job waits for it, saves the report in the job&apos;s artifacts, and the results show up
          here under History. The job fails only if the scan itself fails.
        </p>
      </section>
    </div>
  );
}
