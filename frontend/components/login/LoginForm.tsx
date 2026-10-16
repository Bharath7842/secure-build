"use client";

import { useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";

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

/** Only follow same-origin relative redirects. */
function safeNextPath(): string {
  try {
    const next = new URLSearchParams(window.location.search).get("next");
    if (next && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/login")) return next;
  } catch {
    /* ignore */
  }
  return "/projects";
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
          <span>
            <Icon size={16}>
              <circle cx="12" cy="12" r="10" />
              <path d="M12 8v4M12 16h.01" />
            </Icon>
          </span>
          <span>{message}</span>
        </p>
      )}
    </div>
  );
}

export default function LoginForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [touched, setTouched] = useState({ email: false, password: false });
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

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
        body: JSON.stringify({ email: email.trim(), password, remember }),
      });

      if (res.ok) {
        // Full navigation so the new session is picked up by every server route.
        window.location.assign(safeNextPath());
        return;
      }
      if (res.status === 400 || res.status === 401) {
        setFormError("The email or password is incorrect. Check your details and try again.");
      } else if (res.status === 501) {
        setFormError("Sign-in is not available yet. Contact your administrator for access.");
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
      <form onSubmit={onSubmit} noValidate aria-busy={submitting} className={styles.loginForm}>
        <div className={styles.fieldGroup}>
          <label htmlFor="email" className={styles.fieldLabel}>
            Email address
          </label>
          <div className={styles.fieldShell}>
            <span className={styles.fieldIcon}>
              <Icon>
                <rect x="3" y="5" width="18" height="14" rx="2" />
                <path d="m3 7 9 6 9-6" />
              </Icon>
            </span>
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
              className={`${styles.fieldInput} ${emailError ? styles.fieldInputError : ""}`}
            />
          </div>
          <FieldError id="email-error" message={emailError} />
        </div>

        <div className={styles.fieldGroup}>
          <label htmlFor="password" className={styles.fieldLabel}>
            Password
          </label>
          <div className={styles.fieldShell}>
            <span className={styles.fieldIcon}>
              <Icon>
                <rect x="5" y="11" width="14" height="10" rx="2" />
                <path d="M8 11V7a4 4 0 0 1 8 0v4" />
              </Icon>
            </span>
            <input
              ref={passwordRef}
              id="password"
              name="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              required
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onBlur={() => setTouched((t) => ({ ...t, password: true }))}
              aria-invalid={passwordError ? true : undefined}
              aria-describedby={passwordError ? "password-error" : undefined}
              className={`${styles.fieldInput} ${styles.passwordInput} ${passwordError ? styles.fieldInputError : ""}`}
            />
            <button
              type="button"
              onClick={() => setShowPassword((s) => !s)}
              aria-label={showPassword ? "Hide password" : "Show password"}
              aria-pressed={showPassword}
              className={styles.passwordToggle}
            >
              <Icon>
                {showPassword ? (
                  <>
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                    <path d="m1 1 22 22" />
                  </>
                ) : (
                  <>
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8Z" />
                    <circle cx="12" cy="12" r="3" />
                  </>
                )}
              </Icon>
            </button>
          </div>
          <FieldError id="password-error" message={passwordError} />
        </div>

        <div className={styles.formOptions}>
          <label className={styles.rememberLabel}>
            <input
              type="checkbox"
              name="remember"
              checked={remember}
              onChange={(e) => setRemember(e.target.checked)}
              className={styles.checkbox}
            />
            Remember me
          </label>
        </div>

        {formError && (
          <div
            role="alert"
            className={styles.formError}
          >
            <span>
              <Icon size={18}>
                <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
                <path d="M12 9v4M12 17h.01" />
              </Icon>
            </span>
            <span>{formError}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          aria-disabled={submitting}
          className={`${styles.submitButton} ${submitting ? styles.submitting : ""}`}
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
          {submitting ? "Signing in…" : "Sign in securely"}
          {!submitting && (
            <span className={styles.submitArrow}>
              <Icon>
                <path d="M5 12h14M13 6l6 6-6 6" />
              </Icon>
            </span>
          )}
        </button>
      </form>
      <p role="status" aria-live="polite" aria-atomic="true" className="sr-only">
        {submitting ? "Signing in. Please wait." : ""}
      </p>
    </>
  );
}
