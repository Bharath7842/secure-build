# Server-side request forgery

## What it means

The server fetches a URL supplied by the caller, which can reach internal services or cloud metadata.

## How to fix it

- Prefer allow-lists of permitted hosts and schemes over deny-lists.
- Resolve the host and block loopback, link-local, private and metadata addresses after resolution.
- Do not follow redirects blindly; re-validate each hop.
- Run the fetcher in a network segment with no access to internal services.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
