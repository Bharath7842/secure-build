# Server-side includes (SSI) injection

## What it means

User input reached a page the server processes for SSI directives, and an injected directive (such as an `exec` directive) ran on the server.

## How to fix it

- Disable SSI processing on any file or directory that renders user input, if SSI is not genuinely needed there.
- Where SSI is required, escape or reject the directive delimiter sequence (`<!--#`) in any input before it is written into a page SSI will process.
- Serve user-generated content from a path that is never parsed for SSI.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test asserting an SSI directive in input is rendered literally, not executed.
