import BrandMark from "./BrandMark";
import EvidenceTrace from "./EvidenceTrace";
import styles from "./login.module.css";

export default function BrandPanel() {
  return (
    <aside className={styles.panel} aria-label="About Secure Build">
      <BrandMark />

      <div className={styles.panelBody}>
        <h2 className={styles.headline}>AI agents that trace one issue across every layer.</h2>
        <p className={styles.lede}>
          They scan your code, test your running app and check your infrastructure, then connect what they find into
          one confirmed issue.
        </p>

        <EvidenceTrace />
      </div>
    </aside>
  );
}
