# postMessage listener without an origin check

## What it means

A message listener does not read event.origin before using the data.

## How to fix it

Compare event.origin to an allow-list before reading event.data.

## Verify

Reload the script and confirm the listener returns unless the origin matches.
