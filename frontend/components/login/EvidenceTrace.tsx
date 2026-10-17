"use client";

import { useRef, useState } from "react";
import type { AnimationEvent, CSSProperties } from "react";

import styles from "./login.module.css";

type Token = [kind: "kw" | "str" | "dim" | "flag" | "plain", text: string];

const TOKEN_CLASS: Record<Token[0], string | undefined> = {
  kw: styles.tkKeyword,
  str: styles.tkString,
  dim: styles.tkDim,
  flag: styles.tkFlag,
  plain: undefined,
};

/** One illustrative SQL injection, as each scanner sees it. Paths and hosts are placeholders. */
const EVIDENCE: { module: string; text: string; code: Token[] }[] = [
  {
    module: "SAST",
    text: "ReportDao.java line 88 builds a SQL query from the sort parameter.",
    code: [["str", '"ORDER BY "'], ["plain", " + "], ["flag", "sort"]],
  },
  {
    module: "DAST",
    text: "The endpoint is reachable and fails on a single quote.",
    code: [["kw", "GET"], ["plain", " /api/reports?sort="], ["flag", "name'"], ["dim", "  → 500"]],
  },
  {
    module: "Pentest",
    text: "The agent ran a time-based payload and read the database version.",
    code: [["plain", "sort=name,"], ["flag", "(SELECT pg_sleep(5))"], ["dim", "  5.02 s"]],
  },
  {
    module: "IaC",
    text: "db/main.tf line 31 lets the database accept connections from any address.",
    code: [["plain", "cidr_blocks = ["], ["flag", '"0.0.0.0/0"'], ["plain", "]"]],
  },
];

const stagger = (i: number) => ({ "--i": i }) as CSSProperties;

/**
 * The evidence trace. On load a pulse runs down the rail from SAST to the result, lighting each
 * node as it arrives (all CSS; the timing lives in login.module.css). Hovering or focusing the
 * trace replays the pulse once the previous run has finished. The replay works by flipping
 * `data-run`, which swaps every pulse animation to an identical copy of its keyframes, and a
 * changed animation-name restarts the animation without remounting anything.
 */
export default function EvidenceTrace() {
  const [run, setRun] = useState(0);
  const running = useRef(true);

  function replay() {
    if (running.current) return;
    running.current = true;
    setRun((r) => r + 1);
  }

  function onResultNodeEnd(e: AnimationEvent<HTMLSpanElement>) {
    if (e.target === e.currentTarget) running.current = false;
  }

  return (
    <figure className={styles.traceFigure} onPointerEnter={replay} onFocus={replay}>
      <ol className={styles.trace} data-run={run % 2}>
        {EVIDENCE.map((step, i) => (
          <li key={step.module} className={styles.step} style={stagger(i)}>
            <span className={styles.stepModule}>{step.module}</span>
            <span className={styles.stepNode} aria-hidden="true" />
            <div className={styles.stepBody}>
              <p>{step.text}</p>
              <code className={styles.stepCode}>
                {step.code.map(([kind, text], j) => (
                  <span key={j} className={TOKEN_CLASS[kind]}>
                    {text}
                  </span>
                ))}
              </code>
            </div>
          </li>
        ))}

        <li className={`${styles.step} ${styles.stepResult}`} style={stagger(EVIDENCE.length)}>
          <span className={styles.stepModule}>Verdict</span>
          <span className={styles.stepNode} aria-hidden="true" onAnimationEnd={onResultNodeEnd} />
          <div className={styles.verdict}>
            <div className={styles.verdictHead}>
              <span className={styles.verdictSeverity}>Critical</span>
              <strong>SQL injection in /api/reports</strong>
              <span className={styles.verdictLabel}>Confirmed</span>
            </div>
            <p>
              The AI agent linked the code, the HTTP response, the exploit and the network rule into one issue.
              Fixing the query closes all four.
              <span className={styles.verdictRef}>CWE-89</span>
            </p>
          </div>
        </li>
      </ol>
      <figcaption className={styles.caption}>An example of an AI agent connecting evidence from four scanners.</figcaption>
    </figure>
  );
}
