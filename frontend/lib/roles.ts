import type { DastRole, DastRoleName } from "@/lib/types";

/** One role -> colour mapping, used wherever a role renders (scan form, findings
 *  filter, authorization matrix, report). Admin purple, User blue, Viewer cyan,
 *  Anonymous slate, Custom amber. Class names are written out in full so
 *  Tailwind's source scan picks them up. */
export type RoleTone = "purple" | "blue" | "cyan" | "slate" | "amber";

export const ROLE_TONE: Record<DastRoleName, RoleTone> = {
  admin: "purple",
  user: "blue",
  viewer: "cyan",
  anonymous: "slate",
  custom: "amber",
};

export const ROLE_BADGE_CLASS: Record<RoleTone, string> = {
  purple: "border-purple-200 bg-purple-50 text-purple-700",
  blue: "border-blue-200 bg-blue-50 text-blue-700",
  cyan: "border-cyan-200 bg-cyan-50 text-cyan-700",
  slate: "border-slate-200 bg-slate-100 text-slate-700",
  amber: "border-amber-200 bg-amber-50 text-amber-700",
};

export const ROLE_NAMES = Object.keys(ROLE_TONE) as DastRoleName[];

const DEFAULT_LABEL: Record<DastRoleName, string> = {
  admin: "Admin",
  user: "User",
  viewer: "Viewer",
  anonymous: "Anonymous",
  custom: "Custom",
};

function isRoleName(name: string): name is DastRoleName {
  return name in ROLE_TONE;
}

/** Tone for a role object or a bare role name; unknown names render as custom. */
export function roleTone(role: DastRole | DastRoleName | string): RoleTone {
  const name = typeof role === "string" ? role : role.name;
  return isRoleName(name) ? ROLE_TONE[name] : ROLE_TONE.custom;
}

/** Badge classes (border, background, text) for a role. */
export function roleBadgeClass(role: DastRole | DastRoleName | string): string {
  return ROLE_BADGE_CLASS[roleTone(role)];
}

/** Text shown on a role badge. The role is always shown as text, never by colour alone. */
export function roleLabel(role: DastRole | DastRoleName | string): string {
  if (typeof role !== "string") {
    if (role.name === "custom" && role.label) return role.label;
    return DEFAULT_LABEL[role.name] ?? role.name;
  }
  return isRoleName(role) ? DEFAULT_LABEL[role] : role;
}
