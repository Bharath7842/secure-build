import type { ReactNode } from "react";

import BrandMark from "@/components/login/BrandMark";
import styles from "@/components/login/login.module.css";

import auth from "./auth.module.css";

/** The sign-in page's frame (brand header, centered form, footer), shared
 *  by first-admin setup and the invite/reset password page. */
export default function AuthShell({ title, intro, children }: { title: string; intro?: ReactNode; children: ReactNode }) {
  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <BrandMark tone="light-bg" tagline={false} />
      </header>

      <main className={styles.main}>
        <div className={styles.formWrap}>
          <h1 className={styles.title}>{title}</h1>
          {intro && <div className={auth.aside}>{intro}</div>}
          {children}
        </div>
      </main>

      <footer className={styles.footer}>
        <span>Unified Application Security Platform</span>
        <span>© {new Date().getFullYear()} Secure Build</span>
      </footer>
    </div>
  );
}
