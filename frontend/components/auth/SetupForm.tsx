"use client";

import { useState } from "react";
import type { FormEvent } from "react";

import styles from "@/components/login/login.module.css";

import NewPasswordFields, { newPasswordProblem } from "./NewPasswordFields";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Creates the first admin, then signs them in. */
export default function SetupForm() {
  const [setupToken, setSetupToken] = useState("");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (submitting) return;
    setFormError(null);
    if (!setupToken.trim()) return setFormError("Enter the setup token from the backend .env file.");
    if (!EMAIL_RE.test(email.trim())) return setFormError("Enter a valid email address, like you@company.com.");
    const problem = newPasswordProblem(password, confirm);
    setPasswordError(problem);
    if (problem) return;

    setSubmitting(true);
    try {
      const res = await fetch("/api/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ setup_token: setupToken.trim(), email: email.trim(), display_name: name.trim(), password }),
      });
      const body = (await res.json().catch(() => ({}))) as { redirect?: string; detail?: string; code?: string };
      if (res.ok && body.redirect) {
        window.location.assign(body.redirect);
        return;
      }
      if (body.code === "weak_password") setPasswordError(body.detail ?? "Choose a stronger password.");
      else if (res.status === 404) window.location.assign("/login"); // someone already finished setup
      else setFormError(body.detail ?? "Setup failed. Try again.");
    } catch {
      setFormError("We couldn’t reach the server. Check your connection and try again.");
    }
    setSubmitting(false);
  }

  return (
    <form onSubmit={onSubmit} noValidate aria-busy={submitting} className={styles.form}>
      <div>
        <label htmlFor="setup-token" className={styles.label}>
          Setup token
        </label>
        <input
          id="setup-token"
          type="password"
          autoComplete="off"
          spellCheck={false}
          required
          value={setupToken}
          onChange={(e) => setSetupToken(e.target.value)}
          className={styles.input}
        />
      </div>
      <div>
        <label htmlFor="setup-email" className={styles.label}>
          Email
        </label>
        <input
          id="setup-email"
          type="email"
          inputMode="email"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className={styles.input}
        />
      </div>
      <div>
        <label htmlFor="setup-name" className={styles.label}>
          Your name <span className="font-normal text-[var(--muted)]">(optional)</span>
        </label>
        <input
          id="setup-name"
          autoComplete="name"
          maxLength={120}
          value={name}
          onChange={(e) => setName(e.target.value)}
          className={styles.input}
        />
      </div>
      <NewPasswordFields
        idPrefix="setup"
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
        {submitting ? "Creating account…" : "Create admin account"}
      </button>
    </form>
  );
}
