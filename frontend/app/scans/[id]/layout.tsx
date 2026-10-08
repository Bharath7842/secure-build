/** Scan detail uses a fixed split view — constrain height so left/right panes scroll independently. */
export default function ScanDetailLayout({ children }: { children: React.ReactNode }) {
  return <div className="h-full min-h-0 overflow-hidden">{children}</div>;
}
