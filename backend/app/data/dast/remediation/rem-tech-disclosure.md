# Technology disclosure

## What it means

Headers or pages reveal the server software and version, which helps an attacker pick known exploits.

## How to fix it

- Remove or genericize the `Server`, `X-Powered-By` and similar headers.
- Keep software patched; hiding versions is not a substitute.
- Turn off version banners on error pages.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
