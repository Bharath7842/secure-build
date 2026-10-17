import type { Metadata } from "next";

import BrandMark from "@/components/login/BrandMark";
import BrandPanel from "@/components/login/BrandPanel";
import LoginForm from "@/components/login/LoginForm";
import styles from "@/components/login/login.module.css";

export const metadata: Metadata = {
  title: "Sign in | Secure Build",
  description: "Sign in to Secure Build to see your projects, scans and findings.",
};

export default function LoginPage() {
  return (
    <div className={styles.page}>
      <BrandPanel />

      <main className={styles.formSide}>
        <div className={styles.formWrap}>
          <BrandMark tone="light-bg" className={styles.formBrand} />
          <h1 className={styles.title}>Sign in</h1>

          <LoginForm />
        </div>
      </main>
    </div>
  );
}
