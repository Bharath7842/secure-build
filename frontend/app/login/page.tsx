import type { Metadata } from "next";

import BrandMark from "@/components/login/BrandMark";
import BrandPanel from "@/components/login/BrandPanel";
import LoginForm from "@/components/login/LoginForm";
import styles from "@/components/login/login.module.css";

export const metadata: Metadata = {
  title: "Sign in · Securebuild",
  description: "Sign in to Securebuild, your unified agentic security platform.",
};

export default function LoginPage() {
  return (
    <div className={styles.page}>
      <div className={styles.ambientGlow} aria-hidden="true" />
      <div className={styles.shell}>
        <BrandPanel />

        <main className={styles.formPanel}>
          <header className={styles.mobileHeader}>
            <BrandMark tone="light-bg" />
          </header>

          <div className={styles.panelTopline}>
            <span className={styles.secureSession}>
              <span aria-hidden="true" />
              Encrypted session
            </span>
            <span className={styles.routeLabel}>SECUREBUILD / ACCESS</span>
          </div>

          <div className={styles.formContent}>
            <p className={styles.formKicker}>WELCOME BACK</p>
            <h1>Sign in to your workspace</h1>
            <p className={styles.formDescription}>
              Access your projects, findings, and security posture.
            </p>

            <LoginForm />

            <div className={styles.accessNote}>
              <span>New to Securebuild?</span>
              <span>Ask your workspace administrator for access.</span>
            </div>
          </div>

          <footer className={styles.formFooter}>
            <span>Privacy</span>
            <span aria-hidden="true">•</span>
            <span>Protected workspace access</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
