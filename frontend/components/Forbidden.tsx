import Link from "next/link";

import PageContainer from "@/components/PageContainer";

/** Shown in place of a page the signed-in user isn't allowed to see. */
export default function Forbidden({ landing = "/" }: { landing?: string }) {
  return (
    <PageContainer>
      <div className="mx-auto mt-16 max-w-lg text-center" role="alert">
        <p className="text-sm font-semibold uppercase tracking-wide text-slate-400">403</p>
        <h1 className="mt-2 font-display text-3xl text-[var(--ink)]">You don&apos;t have access to this page</h1>
        <p className="mt-3 text-[var(--muted)]">
          Your account doesn&apos;t include this page. If you need it, ask an administrator to add it to your access.
        </p>
        <Link
          href={landing}
          className="mt-8 inline-block rounded-md bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
        >
          Go to your start page
        </Link>
      </div>
    </PageContainer>
  );
}
