import BrandMark from "./BrandMark";

const FEATURES = [
  {
    label: "Code Analysis",
    icon: <path d="m16 18 6-6-6-6M8 6l-6 6 6 6" />,
  },
  {
    label: "Application Testing",
    icon: (
      <>
        <circle cx="12" cy="12" r="9" />
        <circle cx="12" cy="12" r="4.5" />
        <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
      </>
    ),
  },
  {
    label: "Security Reports",
    icon: (
      <>
        <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
        <path d="M14 3v5h5M9 13h6M9 17h4" />
      </>
    ),
  },
];

/** Code window -> circuit-style routes -> shield. Decorative only. */
function Illustration() {
  const nodes: Array<[number, number]> = [
    [250, 140],
    [250, 100],
    [250, 180],
    [250, 220],
  ];

  return (
    <svg
      viewBox="0 0 520 320"
      fill="none"
      aria-hidden
      focusable="false"
      className="h-auto w-full max-w-[34rem]"
    >
      <defs>
        <linearGradient id="login-shield-fill" x1="400" y1="70" x2="400" y2="258" gradientUnits="userSpaceOnUse">
          <stop stopColor="#3b82f6" stopOpacity="0.28" />
          <stop offset="1" stopColor="#2563eb" stopOpacity="0.06" />
        </linearGradient>
      </defs>

      {/* faint halo behind the shield */}
      <circle cx="400" cy="160" r="128" stroke="#60a5fa" strokeOpacity="0.14" strokeDasharray="2 7" strokeLinecap="round" />
      <circle cx="400" cy="160" r="96" stroke="#60a5fa" strokeOpacity="0.1" />

      {/* code window */}
      <rect x="20" y="90" width="170" height="140" rx="14" fill="#ffffff" fillOpacity="0.04" stroke="#94a3b8" strokeOpacity="0.3" />
      <circle cx="38" cy="107" r="3" fill="#94a3b8" fillOpacity="0.5" />
      <circle cx="50" cy="107" r="3" fill="#94a3b8" fillOpacity="0.35" />
      <circle cx="62" cy="107" r="3" fill="#94a3b8" fillOpacity="0.2" />
      <path d="M20 121h170" stroke="#94a3b8" strokeOpacity="0.18" />
      <g stroke="#60a5fa" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M78 140 52 165l26 25" />
        <path d="m132 140 26 25-26 25" />
        <path d="m113 134-18 62" strokeOpacity="0.7" />
      </g>
      <path d="M38 212h56M38 222h34" stroke="#94a3b8" strokeOpacity="0.28" strokeWidth="3" strokeLinecap="round" />

      {/* routes from code to shield */}
      <g stroke="#60a5fa" strokeOpacity="0.45" strokeWidth="1.5" strokeLinejoin="round">
        <path d="M190 140h60v-40h82" />
        <path d="M190 160h142" />
        <path d="M190 180h60v40h96" />
        <path d="M250 140v40" strokeOpacity="0.25" strokeDasharray="3 4" />
      </g>
      {nodes.map(([cx, cy], i) => (
        <circle
          key={`${cx}-${cy}`}
          cx={cx}
          cy={cy}
          r="3.5"
          fill="#60a5fa"
          className="login-node"
          style={{ animationDelay: `${i * 0.6}s` }}
        />
      ))}
      <circle cx="332" cy="100" r="4" fill="#152238" stroke="#60a5fa" strokeWidth="1.5" />
      <circle cx="332" cy="160" r="4" fill="#152238" stroke="#60a5fa" strokeWidth="1.5" />
      <circle cx="346" cy="220" r="4" fill="#152238" stroke="#60a5fa" strokeWidth="1.5" />

      {/* shield */}
      <path
        d="M400 70 470 96v64c0 50-34 82-70 98-36-16-70-48-70-98V96Z"
        fill="url(#login-shield-fill)"
        stroke="#3b82f6"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path d="M400 88 454 108v52c0 40-26 66-54 80-28-14-54-40-54-80v-52Z" stroke="#93c5fd" strokeOpacity="0.2" strokeLinejoin="round" />
      <path d="m372 160 20 20 38-42" stroke="#e0f2fe" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function BrandPanel() {
  return (
    <aside className="relative hidden overflow-hidden bg-[var(--sidebar)] text-slate-100 lg:flex lg:w-[55%] lg:flex-col lg:justify-between lg:px-14 lg:py-12 xl:px-20">
      {/* faint grid, fading toward the edges */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage:
            "linear-gradient(rgb(148 163 184 / 0.07) 1px, transparent 1px), linear-gradient(90deg, rgb(148 163 184 / 0.07) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
          maskImage: "radial-gradient(ellipse 80% 70% at 55% 50%, #000 30%, transparent 100%)",
          WebkitMaskImage: "radial-gradient(ellipse 80% 70% at 55% 50%, #000 30%, transparent 100%)",
        }}
      />
      {/* restrained blue light */}
      <div
        aria-hidden
        className="pointer-events-none absolute -right-24 top-1/3 h-[32rem] w-[32rem] rounded-full"
        style={{ background: "radial-gradient(circle, rgb(37 99 235 / 0.28) 0%, transparent 65%)" }}
      />

      <div className="relative">
        <BrandMark />
      </div>

      <div className="relative my-10 max-w-xl">
        <p className="font-display text-4xl leading-tight tracking-tight text-white xl:text-5xl">
          Build confidently.
          <br />
          Ship securely.
        </p>
        <p className="mt-5 max-w-md text-base leading-relaxed text-slate-300">
          Find vulnerabilities, review security insights, and protect your applications in one workspace.
        </p>
        <div className="mt-10">
          <Illustration />
        </div>
      </div>

      <ul className="relative flex flex-wrap gap-x-8 gap-y-3 border-t border-white/10 pt-6 text-sm text-slate-400">
        {FEATURES.map((f) => (
          <li key={f.label} className="flex items-center gap-2">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.75"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden
              className="shrink-0 text-blue-400"
            >
              {f.icon}
            </svg>
            {f.label}
          </li>
        ))}
      </ul>
    </aside>
  );
}
