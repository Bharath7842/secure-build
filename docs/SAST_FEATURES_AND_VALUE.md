# Secure Build SAST — Key Features and Value

Secure Build SAST (Static Application Security Testing) checks source code for security weaknesses without running the application. It helps teams find problems earlier, prioritize fixes, and track results.

| Key feature | What it does | Value added |
| --- | --- | --- |
| **Code and project discovery** | Scans a selected repository version and identifies technologies, files, and modules. | Shows where issues belong and connects results to the release being reviewed. |
| **Risk-based scanning** | Prioritizes authentication, database, and other security-sensitive code for deeper review. | Focuses analysis effort on areas where mistakes could have greater impact. |
| **AI-assisted code review** | Examines selected files in context for unsafe behavior and missing protections. | Can uncover problems that simple keyword searches miss. |
| **Security pattern checks** | Checks eligible files for known unsafe coding patterns. | Provides broader coverage with less AI processing. |
| **Cross-file analysis** | Follows supported method calls across files; optional data-flow tooling tracks input into sensitive operations. | Helps explain how a potential vulnerability could be reached. |
| **Secret and configuration checks** | Flags supported hardcoded credential patterns and insecure application or build settings. | Helps identify exposed secrets and risky settings before release. |
| **Finding validation and grouping** | Checks individual occurrences and groups repeated patterns. | Reduces repetitive review and helps distinguish real concerns from harmless matches. |
| **Clear findings and fix guidance** | Shows severity, confirmed/dismissed/unverified status, code location, reasoning, and available remediation guidance. | Helps developers understand what to investigate and fix first. |
| **Review and rescan tracking** | Records review decisions and resolutions, and compares findings between scans. | Makes progress and changed assessments easier to follow. |
| **Reports and exports** | Exports PDF, Excel, SARIF, and JUnit results. | Supports stakeholder reporting, detailed review, and compatible development tools. |
| **Automated release checks** | Integrates with build pipelines and supports configured Critical/High finding thresholds. | Helps teams apply consistent security criteria before release. |
| **AI privacy and cost controls** | Supports approved model endpoints, local-model options, recognized-secret masking, and estimated spending limits. | Gives teams control over where code is processed and how much analysis costs. |

**Typical issues covered:** injection risks, unsafe browser content handling, authorization gaps, hardcoded secrets, weak cryptography, and insecure configuration. Coverage varies by language and enabled analysis.

**Important limits:** Not every file receives deep AI review. Some features require configuration or optional tools. An unverified finding needs investigation, and a scan with no findings does not guarantee secure code. Developers still review, implement, and test fixes.
