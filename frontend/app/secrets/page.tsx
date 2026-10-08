import Link from "next/link";

import ComingSoonPage from "@/components/ComingSoonPage";

export default function SecretsPage() {
  return (
    <ComingSoonPage
      title="Secrets"
      description="Secret scanning finds hardcoded credentials — API keys, database passwords, auth tokens, private keys — that got committed to source, including in git history after they were 'removed' from the latest commit. The goal isn't just finding them: once a secret is in a public or shared repo, it's compromised the moment it's pushed, so the real fix is always to rotate it, not just delete the line."
      note={
        <p className="text-sm text-[var(--muted)]">
          Secret detection already runs as part of a SAST scan today —{" "}
          <Link href="/projects/new" className="font-medium text-[var(--accent)] hover:underline">
            enable it when creating a project
          </Link>
          . This page will host a dedicated secrets view.
        </p>
      }
    />
  );
}
