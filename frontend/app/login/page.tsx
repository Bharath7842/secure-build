import type { Metadata } from "next";

import BrandMark from "@/components/login/BrandMark";
import LoginForm from "@/components/login/LoginForm";
import styles from "@/components/login/login.module.css";

export const metadata: Metadata = {
  title: "Sign in | Secure Build",
  description: "Sign in to Secure Build to see your projects, scans and findings.",
};

export default function LoginPage() {
  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <BrandMark tone="light-bg" tagline={false} />
      </header>

      <main className={styles.main}>
        <div className={styles.formWrap}>
          <h1 className={styles.title}>Sign in to Secure Build</h1>
          <LoginForm />
        </div>
      </main>

      <footer className={styles.footer}>
        <span>Unified Application Security Platform</span>
        <span>© {new Date().getFullYear()} Secure Build</span>
      </footer>
    </div>
  );
}
