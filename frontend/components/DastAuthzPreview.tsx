"use client";

import { roleBadgeClass, roleLabel } from "@/lib/roles";
import type { DastRoleName } from "@/lib/types";

export interface PreviewIdentity {
  label: string;
  role: DastRoleName;
  customName?: string;
}

/** A role as text on a badge: the role is always named, never conveyed by colour alone. */
export function RoleBadge({ role, customName }: { role: DastRoleName; customName?: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${roleBadgeClass(role)}`}
    >
      {roleLabel({ name: role, label: customName })}
    </span>
  );
}

/** Which role pairs the scan will test, from the identities entered so far (no request is made):
 *  every authenticated identity as owner, replayed as each other identity and as Anonymous. */
export default function DastAuthzPreview({ identities }: { identities: PreviewIdentity[] }) {
  const named = identities.filter((i) => i.label.trim());
  const pairs: { owner: PreviewIdentity; actor: string; anonymous: boolean; actorIdentity?: PreviewIdentity }[] = [];
  for (const owner of named) {
    for (const other of named) {
      if (other !== owner) pairs.push({ owner, actor: other.label.trim(), anonymous: false, actorIdentity: other });
    }
    pairs.push({ owner, actor: "Anonymous", anonymous: true });
  }

  return (
    <div className="rounded-md border border-slate-200 bg-slate-50/60 p-3" aria-live="polite">
      <p className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
        Authorization checks that will run
      </p>
      {named.length === 0 ? (
        <p className="mt-1.5 text-sm text-[var(--muted)]">
          No signed-in identity, so there is nothing to replay: only the passive and active checks will run.
          Add an identity to also test access control.
        </p>
      ) : named.length === 1 ? (
        <p className="mt-1.5 text-sm text-[var(--ink)]">
          Only the <strong>anonymous replay</strong> will run: everything {named[0]!.label.trim()} can reach is
          replayed with no session. Add a second identity to test role against role.
        </p>
      ) : (
        <>
          <p className="mt-1.5 text-sm text-[var(--ink)]">
            {pairs.length} role pair{pairs.length === 1 ? "" : "s"}: what each identity can reach is replayed as every
            other identity and as an anonymous visitor.
          </p>
          <ul className="mt-2 grid gap-1 sm:grid-cols-2">
            {pairs.map((pair) => (
              <li
                key={`${pair.owner.label}->${pair.actor}`}
                className="flex flex-wrap items-center gap-1.5 rounded border border-slate-200 bg-white px-2 py-1 text-xs text-[var(--ink)]"
              >
                <span className="font-medium">{pair.owner.label.trim()}</span>
                <RoleBadge role={pair.owner.role} customName={pair.owner.customName} />
                <span aria-hidden>→</span>
                <span className="sr-only">replayed as</span>
                <span className="font-medium">{pair.actor}</span>
                {pair.anonymous ? (
                  <RoleBadge role="anonymous" />
                ) : (
                  pair.actorIdentity && <RoleBadge role={pair.actorIdentity.role} customName={pair.actorIdentity.customName} />
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
