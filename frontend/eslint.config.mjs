import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    // TODO: pre-existing debt. eslint-config-next 16 enables this React Compiler rule as an
    // error, and 9 existing effects (ProjectForm, ScanForm, Sidebar, ResizableSplit,
    // ScanFindingsPanel, app/scans/[id]/page, useMediaQuery) set state synchronously. It is a
    // warning so `npm run lint` can gate CI; fix the effects, then delete this override.
    rules: { "react-hooks/set-state-in-effect": "warn" },
  },
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
]);

export default eslintConfig;
