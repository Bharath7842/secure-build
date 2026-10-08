# Project Vision Statement

## Purpose

Source-code scanning shows what is written in an application, but it cannot show how the application behaves once it is running. Weak access controls, unsafe configuration, and flaws that only appear against a live system stay invisible until a real attacker finds them. The tools that do test running applications have their own problems. They struggle with modern single-page and API-driven applications, and they report so many unproven findings that teams stop trusting the results.

This project adds dynamic security testing to Augmented Secure Build. It tests a running application the way an attacker would and reports only what it can back with evidence. Teams get one place to understand both what is in their code and how their live application holds up.

## Target Users

- **Security engineers and application security teams** who need dependable, repeatable testing of live applications.
- **Development teams** who need clear, actionable findings that tell them what to fix and why.
- **Security consultants** who test client applications and need a report they can hand to the client.
- **Engineering and security leads** who need to see whether risk is going up or down from one scan to the next.

## Value Proposition

- **Findings you can trust.** Every confirmed issue comes with observed proof. A suggestion from the AI is never enough on its own. Anything that cannot be proven is clearly labeled as unverified, and is never hidden or passed off as confirmed.
- **One tool for any kind of application.** Traditional websites, modern single-page apps, and API-only services are all tested without per-target setup.
- **Real authorization testing.** The platform tests what each user role can reach, and what they should not be able to reach. It cross-checks every role against every other, and it also checks what an unauthenticated visitor can see. These are the access flaws that most often lead to real breaches.
- **Safe by design.** Testing stays within the authorized target. Anything that changes data requires explicit opt-in, and a scan can be stopped at any time.
- **Flexible and private.** The platform works with a local AI model or a hosted one, so teams choose where their data goes. It also lets teams choose which security standards a scan tests against, instead of being locked into a fixed set.
- **Part of one platform.** Dynamic findings sit alongside code and dependency findings, in the same views and the same reports.

## Key Features

- Testing of running applications, with or without a login
- Testing as multiple user roles, with a clear view of who can access what
- Findings backed by evidence, with unverified results kept separate and always visible
- Selectable security standards, including the OWASP API and Web Top 10, with the ability to add custom rules
- Live, plain-language progress while a scan runs
- Client-ready reports with remediation guidance and a comparison against the previous scan, showing what is new, fixed, or still open
- Built-in safeguards for scope, intrusiveness, and request rate
