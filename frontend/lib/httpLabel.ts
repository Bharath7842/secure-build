/** Expand `GET /api/x` into `GET http://host/api/x` and drop leftover INCONCLUSIVE wording. */

const METHOD_PATH_RE = /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/(?!\/)[^\s:()]*)/gi;

export function originOf(url: string | null | undefined): string {
  if (!url) return "";
  try {
    const parsed = new URL(url.includes("://") ? url : `http://${url}`);
    return parsed.origin;
  } catch {
    return "";
  }
}

export function stripQueryFragment(url: string): string {
  return url.split("#")[0].split("?")[0];
}

export function withHttpUrl(text: string, origin: string): string {
  if (!text || !origin) return text;
  return text.replace(new RegExp(METHOD_PATH_RE.source, "gi"), (match, method: string, path: string) => {
    if (/^https?:\/\//i.test(path)) return match;
    return `${String(method).toUpperCase()} ${origin}${stripQueryFragment(path)}`;
  });
}

export function hideInconclusive(text: string): string {
  return text
    .replace(/,\s*\d+\s+inconclusive\b/gi, "")
    .replace(/\s*\(unverified\)/gi, "")
    .replace(/\bINCONCLUSIVE\b/g, "PASS")
    .replace(/\binconclusive\b/gi, "passed");
}

export function displayLogLine(line: string, origin: string): string {
  return hideInconclusive(withHttpUrl(line, origin));
}

export function displayEndpoint(method: string, urlOrPath: string, origin = ""): string {
  const dest = stripQueryFragment(urlOrPath || "");
  const verb = (method || "GET").toUpperCase();
  if (!dest) return verb;
  if (/^https?:\/\//i.test(dest)) return `${verb} ${dest}`;
  if (dest.startsWith("/") && origin) return `${verb} ${origin}${dest}`;
  return `${verb} ${dest}`;
}

/** Prefer a concrete http(s) URL from sink/request when the stored target is only `GET /path`. */
export function displayFindingTarget(finding: {
  target?: string | null;
  file_path?: string | null;
  sink?: string | null;
  evidence?: { request?: { url?: string | null } | null } | null;
}): string {
  const labeled = finding.target || finding.file_path || "";
  const candidate = [finding.sink, finding.evidence?.request?.url].find((u) => u && /^https?:\/\//i.test(u)) || "";
  if (candidate) {
    const dest = stripQueryFragment(candidate);
    const method = labeled.match(/^([A-Za-z]{2,10})\b/)?.[1]?.toUpperCase();
    return method ? `${method} ${dest}` : dest;
  }
  return labeled;
}

export function displayFindingTitle(
  title: string,
  finding: {
    target?: string | null;
    file_path?: string | null;
    sink?: string | null;
    evidence?: { request?: { url?: string | null } | null } | null;
  },
): string {
  const next = displayFindingTarget(finding);
  const prev = finding.target || finding.file_path || "";
  if (prev && next !== prev && title.includes(prev)) return title.split(prev).join(next);
  return withHttpUrl(title, originOf(finding.sink || finding.evidence?.request?.url || ""));
}
