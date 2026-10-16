import BrandMark from "./BrandMark";
import styles from "./login.module.css";

const CHECKS = [
  { label: "Code", detail: "SAST", value: "248", state: "clear" },
  { label: "Dependencies", detail: "SCA", value: "91", state: "clear" },
  { label: "Runtime", detail: "DAST", value: "12", state: "testing" },
] as const;

export default function BrandPanel() {
  return (
    <aside className={styles.brandPanel} aria-label="About Securebuild">
      <div className={styles.grid} aria-hidden="true" />
      <div className={styles.brandGlow} aria-hidden="true" />

      <header className={styles.brandHeader}>
        <BrandMark />
        <span className={styles.systemStatus}>
          <span aria-hidden="true" />
          SYSTEMS OPERATIONAL
        </span>
      </header>

      <div className={styles.brandContent}>
        <div className={styles.eyebrow}>
          APPLICATION SECURITY, ORCHESTRATED
        </div>

        <h2 className={styles.headline}>
          Ship fast.
          <br />Stay <span>secure.</span>
        </h2>

        <p className={styles.description}>
          One intelligent layer across code, dependencies, and runtime—so every release moves with confidence.
        </p>

        <div className={styles.postureCard}>
          <div className={styles.postureHeader}>
            <div>
              <span className={styles.postureLabel}>LIVE SECURITY POSTURE</span>
              <strong>Everything in view.</strong>
            </div>
            <div className={styles.postureScore}>
              <strong>94</strong>
              <span>/ 100</span>
            </div>
          </div>

          <div className={styles.postureMeter} aria-label="Security posture score: 94 out of 100">
            <span />
          </div>

          <ul className={styles.checks}>
            {CHECKS.map((check) => (
              <li key={check.label}>
                <span className={styles.checkIcon} aria-hidden="true">
                  {check.state === "clear" ? (
                    <svg viewBox="0 0 20 20" fill="none">
                      <path d="m5.5 10.2 2.7 2.7 6.3-6.3" />
                    </svg>
                  ) : (
                    <span className={styles.testingRing} />
                  )}
                </span>
                <span className={styles.checkName}>
                  <strong>{check.label}</strong>
                  <small>{check.detail}</small>
                </span>
                <span className={styles.checkValue}>{check.value}</span>
                <span className={check.state === "clear" ? styles.clearState : styles.testingState}>
                  {check.state === "clear" ? "CLEAR" : "TESTING"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <footer className={styles.brandFooter}>
        <span>SECURE FROM COMMIT TO RUNTIME</span>
        <span>01 — 03</span>
      </footer>
    </aside>
  );
}
