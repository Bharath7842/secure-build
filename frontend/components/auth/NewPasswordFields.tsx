"use client";

import { useState } from "react";

import styles from "@/components/login/login.module.css";

import auth from "./auth.module.css";

export const MIN_PASSWORD_LENGTH = 12;

/** What's wrong with a new password pair, checked before submitting. The
 *  backend applies the full policy (common passwords, not your email). */
export function newPasswordProblem(password: string, confirm: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return `Use at least ${MIN_PASSWORD_LENGTH} characters.`;
  if (password !== confirm) return "The two passwords don't match.";
  return null;
}

/** "New password" + "Confirm" with a show/hide toggle. Paste and password
 *  managers work (autocomplete="new-password"). */
export default function NewPasswordFields({
  password,
  confirm,
  onPassword,
  onConfirm,
  error,
  idPrefix = "new",
}: {
  password: string;
  confirm: string;
  onPassword: (value: string) => void;
  onConfirm: (value: string) => void;
  error?: string | null;
  idPrefix?: string;
}) {
  const [show, setShow] = useState(false);
  const errorId = `${idPrefix}-password-error`;
  return (
    <>
      <div>
        <label htmlFor={`${idPrefix}-password`} className={styles.label}>
          New password
        </label>
        <div className={styles.passwordField}>
          <input
            id={`${idPrefix}-password`}
            type={show ? "text" : "password"}
            autoComplete="new-password"
            required
            minLength={MIN_PASSWORD_LENGTH}
            value={password}
            onChange={(e) => onPassword(e.target.value)}
            aria-invalid={error ? true : undefined}
            aria-describedby={`${idPrefix}-password-help${error ? ` ${errorId}` : ""}`}
            className={`${styles.input} ${styles.passwordInput} ${error ? styles.inputError : ""}`}
          />
          <button
            type="button"
            onClick={() => setShow((s) => !s)}
            aria-label={show ? "Hide passwords" : "Show passwords"}
            aria-pressed={show}
            className={styles.passwordToggle}
          >
            {show ? "Hide" : "Show"}
          </button>
        </div>
        <p id={`${idPrefix}-password-help`} className={auth.helper}>
          At least {MIN_PASSWORD_LENGTH} characters. A few unrelated words make a strong, memorable password.
        </p>
      </div>
      <div>
        <label htmlFor={`${idPrefix}-confirm`} className={styles.label}>
          Confirm new password
        </label>
        <input
          id={`${idPrefix}-confirm`}
          type={show ? "text" : "password"}
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(e) => onConfirm(e.target.value)}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? errorId : undefined}
          className={`${styles.input} ${error ? styles.inputError : ""}`}
        />
        <div id={errorId} aria-live="polite">
          {error && <p className={styles.fieldError}>{error}</p>}
        </div>
      </div>
    </>
  );
}
