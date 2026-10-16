/** Securebuild shield mark + wordmark. */
export default function BrandMark({
  tone = "dark-bg",
  className = "",
}: {
  /** "dark-bg" for the navy panel, "light-bg" for the white card. */
  tone?: "dark-bg" | "light-bg";
  className?: string;
}) {
  return (
    <div className={`flex items-center gap-3 ${tone === "dark-bg" ? "text-white" : "text-[var(--ink)]"} ${className}`}>
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="38"
        height="40"
        viewBox="0 0 38 40"
        fill="none"
        aria-hidden
        className="shrink-0"
      >
        <path d="m19 2 15 6v12c0 8-6 14-15 18C10 34 4 28 4 20V8z" fill="#3778f6" />
        <path d="m19 2 15 6v12c0 8-6 14-15 18V2Z" fill="#2563eb" />
        <path d="m13 14-4 5 4 5m12-10 4 5-4 5m-4-11-4 13" stroke="white" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span className="text-[1.375rem] font-semibold tracking-[-0.04em]">Securebuild<span className="text-[#76a4ff]">.</span></span>
    </div>
  );
}
