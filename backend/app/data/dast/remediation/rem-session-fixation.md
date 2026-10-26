# Session fixation

## What it means

The session cookie was not rotated at login.

## How to fix it

Issue a new session identifier when authentication succeeds and invalidate the previous one.

## Verify

Log in again and confirm the session cookie value changes.
