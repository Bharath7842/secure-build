import type { Metadata } from "next";

import AcceptLinkForm from "@/components/auth/AcceptLinkForm";
import AuthShell from "@/components/auth/AuthShell";

export const metadata: Metadata = {
  title: "Set your password | Secure Build",
  description: "Choose a password for your Secure Build account.",
  // The page is opened from a one-time link; don't leak its address onward.
  referrer: "no-referrer",
};

/** Opened from an admin's invite or password-reset link. */
export default function AccountSetupPage() {
  return (
    <AuthShell
      title="Set your password"
      intro="Choose a password for your Secure Build account. This link works once and expires, so finish now."
    >
      <AcceptLinkForm />
    </AuthShell>
  );
}
