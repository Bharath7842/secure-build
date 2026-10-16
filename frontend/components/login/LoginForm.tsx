"use client";

import { useRef, useState } from "react";
import type { FormEvent } from "react";

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

const FIELD_BASE =
  "block h-12 w-full rounded-lg border bg-white px-3.5 text-base text-[var(--ink)] shadow-sm outline-none transition-[border-color,box-shadow] duration-150 placeholder:text-slate-400";
const FIELD_OK =
  "border-slate-300 hover:border-slate-400 focus:border-[var(--accent)] focus:ring-4 focus:ring-[var(--accent)]/15";
const FIELD_ERR = "border-red-500 focus:border-red-500 focus:ring-4 focus:ring-red-500/15";

function FieldError({ id, message }: { id: string; message: string }) {
  return (
    <p id={id} className="mt-1.5 flex items-start gap-1.5 text-sm text-red-600">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden
        className="mt-0.5 shrink-0"
      >
        <circle cx="12" cy="12" r="10" />
        <path d="M12 8v4M12 16h.01" />
      </svg>
      <span>{message}</span>
    </p>
  );
}

export default function LoginForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
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
        body: JSON.stringify({ email: email.trim(), password }),
      });

      if (res.ok) {
        // Full navigation so the new session is picked up by every server route.
        window.location.assign(safeNextPath());
        return;
      }
      if (res.status === 400 || res.status === 401) {
        setFormError("The email or password is incorrect. Check your details and try again.");
      } else if (res.status === 501) {
        setFormError("Sign-in isn’t set up for this environment yet. Ask your administrator to enable authentication.");
      } else {
        setFormError("We couldn’t sign you in right now. Please try again in a moment.");
      }
    } catch {
      setFormError("We couldn’t reach the server. Check your connection and try again.");
    }
    setSubmitting(false);
  }

  return (
    <form onSubmit={onSubmit} noValidate aria-busy={submitting} className="mt-8 space-y-5">
      <div>
        <label htmlFor="email" className="block text-sm font-semibold text-[var(--ink)]">
          Email address
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
          className={`${FIELD_BASE} mt-1.5 ${emailError ? FIELD_ERR : FIELD_OK}`}
        />
        {emailError && <FieldError id="email-error" message={emailError} />}
      </div>

      <div>
        <label htmlFor="password" className="block text-sm font-semibold text-[var(--ink)]">
          Password
        </label>
        <div className="relative mt-1.5">
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
            className={`${FIELD_BASE} pr-14 ${passwordError ? FIELD_ERR : FIELD_OK}`}
          />
          <button
            type="button"
            onClick={() => setShowPassword((s) => !s)}
            aria-label={showPassword ? "Hide password" : "Show password"}
            aria-pressed={showPassword}
            className="absolute right-0.5 top-0.5 flex h-11 w-11 items-center justify-center rounded-md text-slate-500 transition-colors hover:bg-slate-100 hover:text-[var(--ink)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.75"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden
            >
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
            </svg>
          </button>
        </div>
        {passwordError && <FieldError id="password-error" message={passwordError} />}
      </div>

      {formError && (
        <div
          role="alert"
          className="flex items-start gap-2.5 rounded-lg border border-red-200 bg-red-50 px-3.5 py-3 text-sm text-red-800"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="18"
            height="18"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden
            className="mt-px shrink-0"
          >
            <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
            <path d="M12 9v4M12 17h.01" />
          </svg>
          <span>{formError}</span>
        </div>
      )}

      <button
        type="submit"
        aria-disabled={submitting}
        className={`flex h-12 w-full items-center justify-center gap-2 rounded-lg bg-[var(--accent)] text-base font-semibold text-white shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-[var(--accent)]/30 ${
          submitting ? "cursor-wait opacity-90" : "hover:bg-blue-700 active:bg-blue-800"
        }`}
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
            className="animate-spin motion-reduce:animate-none"
          >
            <path d="M21 12a9 9 0 1 1-6.2-8.56" />
          </svg>
        )}
        {submitting ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
