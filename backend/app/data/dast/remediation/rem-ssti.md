# Server-side template injection (SSTI)

## What it means

User input reached a template engine as template syntax rather than as data, so an expression in the input was evaluated by the server.

## How to fix it

- Never pass user input into a template string that the engine will parse as a template. Pass it only as a *value* a trusted, pre-written template renders.
- Use a logic-less or sandboxed template mode where the engine offers one, and disable any feature that evaluates arbitrary expressions.
- Treat a template engine the same as a code interpreter: input should never influence which template or expression runs.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test asserting a template expression in input is rendered literally, not evaluated.
