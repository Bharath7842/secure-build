const KEY = (projectId: string) => `sb-scheduled-short-ids:${projectId}`;

function normalize(id: string): string {
  return id.trim().toUpperCase();
}

export function loadScheduledShortIds(projectId: string): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY(projectId));
    const parsed = raw ? (JSON.parse(raw) as unknown) : [];
    if (!Array.isArray(parsed)) return [];
    return [...new Set(parsed.map((id) => normalize(String(id))).filter(Boolean))];
  } catch {
    return [];
  }
}

export function saveScheduledShortIds(projectId: string, ids: Iterable<string>): void {
  if (typeof window === "undefined") return;
  const unique = [...new Set([...ids].map(normalize).filter(Boolean))];
  window.localStorage.setItem(KEY(projectId), JSON.stringify(unique));
}

export function isScheduled(ids: ReadonlySet<string>, shortId: string | null | undefined): boolean {
  return Boolean(shortId && ids.has(normalize(shortId)));
}
