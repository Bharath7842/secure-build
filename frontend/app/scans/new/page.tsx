import NewScanForm from "@/components/NewScanForm";
import PageContainer from "@/components/PageContainer";

export default async function NewScanPage({
  searchParams,
}: {
  searchParams: Promise<{ type?: string; from?: string }>;
}) {
  const { type, from } = await searchParams;
  const scanType =
    type === "sca" ? "sca" : type === "sbom" ? "sbom" : type === "dast" ? "dast" : "sast";
  const isSca = scanType === "sca";
  const isSbom = scanType === "sbom";
  const isDast = scanType === "dast";

  return (
    <PageContainer>
      <div className="max-w-3xl">
        <h1 className="font-display text-3xl text-[var(--ink)]">
          {isSca
            ? "SCA Dependency Scan"
            : isSbom
              ? "SBOM Generation"
              : isDast
                ? "DAST Scan"
                : "SAST SCAN"}
        </h1>
        <p className="mt-2 text-sm text-[var(--muted)]">
          {isSca
            ? "Scan a project's dependency manifests for known-vulnerable versions via OSV.dev."
            : isSbom
              ? "Generate a CycloneDX/SPDX component inventory from a project's dependency manifests, with a best-effort license and cost classification for each component."
              : isDast
                ? "Crawl a running web application — optionally logging in first — to discover its pages, forms and API endpoints."
                : "Trigger a security scan for a project's repository. Choose whether to use an LLM for this run, and pick the model when enabled."}
        </p>
        <div className="mt-8">
          <NewScanForm scanType={scanType} fromScanId={isDast ? from : undefined} />
        </div>
      </div>
    </PageContainer>
  );
}
