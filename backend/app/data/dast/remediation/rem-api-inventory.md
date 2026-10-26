# Improper inventory management

## What it means

Endpoints exist that the published API description does not list, such as old versions, debug routes or shadow services.

## How to fix it

- Maintain one authoritative API description and generate documentation from it.
- Retire old API versions or protect them to the same standard.
- Remove debug and test endpoints from production builds.
- Compare the deployed routes against the description in CI.

## Verify

Re-run the scan and confirm the finding no longer appears; add a regression test for the behaviour you changed.
