import type { Metadata } from "next";
import { redirect } from "next/navigation";

import AuthShell from "@/components/auth/AuthShell";
import SetupForm from "@/components/auth/SetupForm";
import { sastFetch } from "@/lib/server-sast";

export const metadata: Metadata = {
  title: "Set up | Secure Build",
  description: "Create the first administrator account for Secure Build.",
};

type SetupStatus = { open: boolean; configured: boolean; has_users: boolean };

/** First-admin setup. Only usable while there are no accounts at all and the
 *  operator has the SETUP_TOKEN from the server; afterwards it redirects to sign-in. */
export default async function SetupPage() {
  let status: SetupStatus | null = null;
  try {
    const res = await sastFetch("/setup/status");
    if (res.ok) status = (await res.json()) as SetupStatus;
  } catch {
    status = null;
  }
  if (status?.has_users) redirect("/login");

  if (!status) {
    return (
      <AuthShell title="Set up Secure Build" intro="We couldn’t reach the backend. Check that it’s running, then reload this page.">
        {null}
      </AuthShell>
    );
  }

  if (!status.configured) {
    return (
      <AuthShell
        title="Set up Secure Build"
        intro={
          <>
            <p>
              To create the first admin account, set <code>SETUP_TOKEN</code> in the backend <code>.env</code> to a
              random value of at least 32 characters, then restart the backend and reload this page.
            </p>
            <p className="mt-3">
              For example: <code>python -c &quot;import secrets; print(secrets.token_urlsafe(32))&quot;</code>
            </p>
          </>
        }
      >
        {null}
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Create the first admin"
      intro="There are no accounts yet. Enter the SETUP_TOKEN from the backend .env file to create the administrator account. This page closes once it exists."
    >
      <SetupForm />
    </AuthShell>
  );
}
