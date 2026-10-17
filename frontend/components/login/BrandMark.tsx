/** Secure Build logo lockup: a shield carrying a code symbol, the Georgia wordmark the sidebar
 *  uses, and the product tagline underneath. */
export default function BrandMark({
  tone = "dark-bg",
  className = "",
}: {
  /** "dark-bg" on the navy panel, "light-bg" on the canvas. */
  tone?: "dark-bg" | "light-bg";
  className?: string;
}) {
  const dark = tone === "dark-bg";
  return (
    <span className={`inline-flex items-center gap-3 ${className}`}>
      <svg width="38" height="43" viewBox="0 0 32 36" fill="none" aria-hidden="true" className="shrink-0">
        <path d="M16 1.5 29 6.5v10c0 8-5.5 14-13 17.5C8.5 30.5 3 24.5 3 16.5v-10z" fill="#2563eb" />
        <path d="M16 1.5 29 6.5v10c0 8-5.5 14-13 17.5z" fill="#1d4ed8" />
        <path
          d="m11.5 13-4 4.5 4 4.5m9-9 4 4.5-4 4.5M17.6 11.5l-3.2 12"
          stroke="#fff"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <span className="flex flex-col">
        <span className={`font-display text-2xl leading-tight tracking-wide ${dark ? "text-white" : "text-[var(--ink)]"}`}>
          Secure Build
        </span>
        <span className={`mt-0.5 text-xs font-medium ${dark ? "text-[#a9b6c9]" : "text-[var(--muted)]"}`}>
          Unified Application Security Platform
        </span>
      </span>
    </span>
  );
}
