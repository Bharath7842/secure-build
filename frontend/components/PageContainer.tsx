import type { ReactNode } from "react";

/**
 * Standard page padding, applied per-page now that the root layout is full-bleed
 * (needed so routes like the scan detail split view can go edge-to-edge).
 */
export default function PageContainer({ children }: { children: ReactNode }) {
  return <div className="px-12 py-10">{children}</div>;
}
