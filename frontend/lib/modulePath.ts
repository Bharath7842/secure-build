/** Strip workspace/env absolute prefixes; show repo-relative module paths. */

const WORKSPACE_UUID = /(?:^|\/)workspaces\/[0-9a-fA-F-]{36}\/(.+)$/i;

const MODULE_ROOTS = new Set([
  "src",
  "app",
  "apps",
  "backend",
  "frontend",
  "packages",
  "services",
  "lib",
  "libs",
  "modules",
  "server",
  "client",
  "web",
  "api",
  "cmd",
  "internal",
  "pkg",
]);

export function toModulePath(path: string | null | undefined): string {
  if (!path) return "—";
  let p = path.replace(/\\/g, "/").trim();
  if (!p) return "—";

  if (p.startsWith("file://")) {
    p = p.slice(7);
    if (/^\/[A-Za-z]:\//.test(p)) p = p.slice(1);
  }

  const workspaceMatch = WORKSPACE_UUID.exec(p);
  if (workspaceMatch?.[1]) return workspaceMatch[1];

  const isAbs = /^[A-Za-z]:\//.test(p) || p.startsWith("/");
  if (isAbs) {
    let parts = p.split("/").filter((part) => part && part !== ".");
    if (parts[0] && /^[A-Za-z]:$/.test(parts[0])) parts = parts.slice(1);
    const rootIdx = parts.findIndex((part) => MODULE_ROOTS.has(part.toLowerCase()));
    if (rootIdx >= 0) return parts.slice(rootIdx).join("/");
    if (parts.length > 2) return parts.slice(-3).join("/");
    return parts.join("/");
  }

  return p.replace(/^\.\//, "");
}
