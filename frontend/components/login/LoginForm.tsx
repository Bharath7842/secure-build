"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";

import auth from "@/components/auth/auth.module.css";

import styles from "./login.module.css";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateEmail(value: string): string | null {
  const v = value.trim();
  if (!v) return "Enter your email address.";
  if (!EMAIL_RE.test(v)) return "Enter a valid email address, like you@company.com.";
  return null;
}

function validatePassword(value: string): string | null {
  return value ? null : "Enter your password.";
}

function searchParam(name: string): string | null {
  try {
    return new URLSearchParams(window.location.search).get(name);
  } catch {
    return null;
  }
}

function Icon({ children, size = 20 }: { children: ReactNode; size?: number }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      {children}
    </svg>
  );
}

function FieldError({ id, message }: { id: string; message: string | null }) {
  return (
    <div id={id} aria-live="polite" aria-atomic="true">
      {message && (
        <p className={styles.fieldError}>
          <Icon size={16}>
            <circle cx="12" cy="12" r="10" />
            <path d="M12 8v4M12 16h.01" />
          </Icon>
          <span>{message}</span>
        </p>
      )}
    </div>
  );
}

export default function LoginForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [remember, setRemember] = useState(false);
  const [setupOpen, setSetupOpen] = useState(false);
  const [touched, setTouched] = useState({ email: false, password: false });
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  const expired = useSearchParams().get("reason") === "expired";

  useEffect(() => {
    // A brand-new install has no accounts yet: point at first-admin setup.
    fetch("/api/setup/status", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((body) => setSetupOpen(Boolean(body?.open)))
      .catch(() => {});
  }, []);

  const emailError = touched.email ? validateEmail(email) : null;
  const passwordError = touched.password ? validatePassword(password) : null;

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (submitting) return;

    setTouched({ email: true, password: true });
    setFormError(null);

    if (validateEmail(email)) {
      emailRef.current?.focus();
      return;
    }
    if (validatePassword(password)) {
      passwordRef.current?.focus();
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // The server decides where to go: `next` if it's safe and allowed, else the start page.
        body: JSON.stringify({ email: email.trim(), password, remember, next: searchParam("next") }),
      });

      if (res.ok) {
        const { redirect } = (await res.json()) as { redirect: string };
        // Full navigation so the new session is picked up by every server route.
        window.location.assign(redirect);
        return;
      }
      if (res.status === 400 || res.status === 401) {
        setFormError("The email or password is incorrect. Check your details and try again.");
      } else if (res.status === 429) {
        const body = (await res.json().catch(() => null)) as { detail?: string } | null;
        setFormError(body?.detail ?? "Too many attempts. Wait a few minutes and try again.");
      } else {
        setFormError("We couldn’t sign you in right now. Please try again in a moment.");
      }
    } catch {
      setFormError("We couldn’t reach the server. Check your connection and try again.");
    }
    setSubmitting(false);
  }

  return (
    <>
      <form onSubmit={onSubmit} noValidate aria-busy={submitting} className={styles.form}>
        {expired && (
          <div role="status" className={auth.notice}>
            <Icon size={18}>
              <circle cx="12" cy="12" r="10" />
              <path d="M12 6v6l4 2" />
            </Icon>
            <span>Your session ended. Sign in again to continue where you left off.</span>
          </div>
        )}

        <div>
          <label htmlFor="email" className={styles.label}>
            Work email
          </label>
          <input
            ref={emailRef}
            id="email"
            name="email"
            type="email"
            inputMode="email"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            required
            placeholder="you@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onBlur={() => setTouched((t) => ({ ...t, email: true }))}
            aria-invalid={emailError ? true : undefined}
            aria-describedby={emailError ? "email-error" : undefined}
            className={`${styles.input} ${emailError ? styles.inputError : ""}`}
          />
          <FieldError id="email-error" message={emailError} />
        </div>

        <div>
          <label htmlFor="password" className={styles.label}>
            Password
          </label>
          <div className={styles.passwordField}>
            <input
              ref={passwordRef}
              id="password"
              name="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onBlur={() => setTouched((t) => ({ ...t, password: true }))}
              aria-invalid={passwordError ? true : undefined}
              aria-describedby={passwordError ? "password-error" : undefined}
              className={`${styles.input} ${styles.passwordInput} ${passwordError ? styles.inputError : ""}`}
            />
            <button
              type="button"
              onClick={() => setShowPassword((s) => !s)}
              aria-label={showPassword ? "Hide password" : "Show password"}
              aria-pressed={showPassword}
              className={styles.passwordToggle}
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>
          <FieldError id="password-error" message={passwordError} />
        </div>

        <label className={auth.checkRow}>
          <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
          Keep me signed in on this device
        </label>

        {formError && (
          <div role="alert" className={styles.formError}>
            <Icon size={18}>
              <circle cx="12" cy="12" r="10" />
              <path d="M12 8v4M12 16h.01" />
            </Icon>
            <span>{formError}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          aria-disabled={submitting}
          className={styles.submit}
        >
          {submitting && (
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
              strokeLinecap="round"
              aria-hidden
              className={styles.spinner}
            >
              <path d="M21 12a9 9 0 1 1-6.2-8.56" />
            </svg>
          )}
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
      <p className={auth.aside}>
        Forgot your password? Ask your administrator for a reset link.
        {setupOpen && (
          <>
            {" "}
            First time here?{" "}
            <Link href="/setup" className={auth.link}>
              Set up the first admin account
            </Link>
            .
          </>
        )}
      </p>
      <p role="status" aria-live="polite" aria-atomic="true" className="sr-only">
        {submitting ? "Signing in. Please wait." : ""}
      </p>
    </>
  );
}
