import type { AppUser } from "@/lib/access";

const STATUS_CLASS: Record<AppUser["status"], string> = {
  active: "bg-emerald-50 text-emerald-700",
  invited: "bg-amber-50 text-amber-800",
  disabled: "bg-slate-100 text-slate-600",
};

const STATUS_LABEL: Record<AppUser["status"], string> = {
  active: "Active",
  invited: "Invited",
  disabled: "Disabled",
};

/** Account status, always as text (never colour alone). */
export function StatusBadge({ status }: { status: AppUser["status"] }) {
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_CLASS[status]}`}>{STATUS_LABEL[status]}</span>
  );
}

export function RoleBadge({ role }: { role: AppUser["role"] }) {
  return (
    <span
      className={`rounded-full border px-2 py-0.5 text-xs font-medium ${
        role === "admin" ? "border-purple-200 bg-purple-50 text-purple-700" : "border-slate-200 bg-white text-slate-700"
      }`}
    >
      {role === "admin" ? "Admin" : "User"}
    </span>
  );
}

export function formatWhen(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";
}
