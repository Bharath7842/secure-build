"use client";

import { useState } from "react";

function formatExpiry(iso: string): string {
  const hours = Math.round((new Date(iso).getTime() - Date.now()) / 3_600_000);
  const when = new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  return hours >= 1 ? `in about ${hours} hour${hours === 1 ? "" : "s"} (${when})` : `at ${when}`;
}

/**
 * An invite or reset link, shown once. It isn't stored anywhere the admin
 * can come back to, so the copy button and the warning matter.
 */
export default function OneTimeLinkPanel({
  url,
  expiresAt,
  kind,
}: {
  url: string;
  expiresAt: string;
  kind: "invite" | "reset";
}) {
  const [copied, setCopied] = useState<"yes" | "failed" | null>(null);

  async function copy() {
    try {
      await navigator.clipboard.writeText(url);
      setCopied("yes");
    } catch {
      setCopied("failed");
    }
  }

  return (
    <div className="rounded-md border border-amber-200 bg-amber-50 p-4 text-sm">
      <p className="font-medium text-amber-900">
        {kind === "invite" ? "Invite link" : "Password reset link"}: shown only once
      </p>
      <p className="mt-1 text-amber-900/80">
        Copy it now and send it to the person directly (chat or email). It works once and expires {formatExpiry(expiresAt)}.
        {kind === "reset" && " Using it signs them out everywhere."}
      </p>
      <div className="mt-3 flex gap-2">
        <label className="sr-only" htmlFor="one-time-link">
          {kind === "invite" ? "Invite link" : "Reset link"}
        </label>
        <input
          id="one-time-link"
          readOnly
          value={url}
          onFocus={(e) => e.currentTarget.select()}
          className="min-w-0 flex-1 rounded-md border border-amber-300 bg-white px-3 py-2 font-mono text-xs text-[var(--ink)]"
        />
        <button
          type="button"
          onClick={copy}
          className="shrink-0 rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
        >
          Copy link
        </button>
      </div>
      <p aria-live="polite" className="mt-2 min-h-[1.25rem] text-xs text-amber-900">
        {copied === "yes" ? "Copied to the clipboard." : copied === "failed" ? "Couldn't copy automatically; select the link and copy it." : ""}
      </p>
    </div>
  );
}
