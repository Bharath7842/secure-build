/** Secure Build shield mark + wordmark. The wordmark matches the sidebar (Georgia display face). */
export default function BrandMark({ className = "" }: { className?: string }) {
  return (
    <div className={`flex items-center gap-2.5 text-white ${className}`}>
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="28"
        height="28"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden
        className="shrink-0 text-blue-400"
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
        <path d="m8.5 12 2.5 2.5 4.5-5" className="text-white" />
      </svg>
      <span className="font-display text-2xl tracking-wide">Secure Build</span>
    </div>
  );
}
