# OS command injection

## What it means

User input reaches a shell command line, so an attacker can run arbitrary commands.

## How to fix it

- Avoid invoking a shell. Use library APIs for the task instead.
- If a process must run, pass arguments as an array with no shell and validate each against an allow-list.
- Run the service with least privilege and in a restricted environment.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
