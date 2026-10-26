# Path traversal / local file inclusion

## What it means

A filename or path built from user input let the request escape the intended directory and read a file the application never meant to serve.

## How to fix it

- Never build a filesystem path directly from input. Map input to a fixed set of allowed values (an allowlist or lookup table) instead of a path fragment.
- If a path must be built from input, resolve it to an absolute path and reject anything that does not stay under the intended base directory.
- Run the application with a filesystem user that cannot read files outside the application's own directories.
- Reject path separators, `..`, and encoded variants of them in the input before it ever reaches file-opening code.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test asserting a traversal payload is rejected rather than resolved.
