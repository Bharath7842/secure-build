"use client";

import Link from "next/link";
import { useState } from "react";
import type { FormEvent } from "react";

import styles from "@/components/login/login.module.css";

import auth from "./auth.module.css";
import NewPasswordFields, { newPasswordProblem } from "./NewPasswordFields";

/** The link's one-time token. It travels in the URL fragment (#t=...), which
 *  browsers never send to a server, so it stays out of server and proxy logs. */
function tokenFromUrl(): string {
  return new URLSearchParams(window.location.hash.replace(/^#/, "")).get("t") ?? "";
}

/** Sets a password from an invite or reset link. */
export default function AcceptLinkForm() {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [doneFor, setDoneFor] = useState<string | null>(null);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (submitting) return;
    setFormError(null);
    const token = tokenFromUrl();
    if (!token) {
      setFormError("This link is incomplete. Open the full link you were sent, or ask your administrator for a new one.");
      return;
    }
    const problem = newPasswordProblem(password, confirm);
    setPasswordError(problem);
    if (problem) return;

    setSubmitting(true);
    try {
      const res = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      const body = (await res.json().catch(() => ({}))) as { email?: string; detail?: string; code?: string };
      if (res.ok) {
        // The token is used up; drop it from the address bar and history.
        window.history.replaceState(null, "", window.location.pathname);
        setDoneFor(body.email ?? "");
      } else if (body.code === "weak_password") {
        setPasswordError(body.detail ?? "Choose a stronger password.");
      } else {
        setFormError(body.detail ?? "We couldn’t set your password. Try again.");
      }
    } catch {
      setFormError("We couldn’t reach the server. Check your connection and try again.");
    }
    setSubmitting(false);
  }

  if (doneFor !== null) {
    return (
      <div className={styles.form}>
        <div role="status" className={`${auth.notice} ${auth.success}`}>
          <span>
            Your password is set{doneFor ? ` for ${doneFor}` : ""}. You can sign in now.
          </span>
        </div>
        <Link href="/login" className={styles.submit}>
          Go to sign in
        </Link>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} noValidate aria-busy={submitting} className={styles.form}>
      <NewPasswordFields
        idPrefix="link"
        password={password}
        confirm={confirm}
        onPassword={setPassword}
        onConfirm={setConfirm}
        error={passwordError}
      />
      {formError && (
        <div role="alert" className={styles.formError}>
          <span>{formError}</span>
        </div>
      )}
      <button type="submit" disabled={submitting} className={styles.submit}>
        {submitting ? "Saving…" : "Set password"}
      </button>
    </form>
  );
}
