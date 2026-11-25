# Langfuse (optional)

Shows every SAST LLM call in a local [Langfuse](https://langfuse.com): prompt, answer, tokens, cost,
latency, errors. One trace and one session per scan. Secure Build works the same without it.

```bash
cd dev/langfuse
./setup.sh          # first run: generates secrets, starts the stack, adds LANGFUSE_* to the root .env
./setup.sh stop     # stop it, keep the data
docker compose down -v    # remove it and delete all traces
```

Restart the backend after the first run. Open <http://localhost:3200> and sign in with
`ADMIN_EMAIL` / `ADMIN_PASSWORD` from `dev/langfuse/.env`.

To turn tracing off, remove `LANGFUSE_HOST` from the root `.env` and restart the backend. If Langfuse
is only stopped, scans carry on: tracing pauses for 60 s at a time and those calls are not recorded.

The stack needs about 3 GB of Docker memory. Next to a large local model, stop it when you don't need it.

## Security

- Traces contain repository code. The host must be loopback or approved (`LLM_ALLOWED_HOSTS` or the
  admin LLM policy page), otherwise tracing stays off and the backend logs why. A public https host
  such as Langfuse Cloud is **not** accepted unless approved.
- Secret values are masked before sending, even for a project with `secret-masking` off.
- Only the web UI is published, on `127.0.0.1:3200`. The databases and the worker are on a network
  without internet access. Sign-up and telemetry are off. All passwords are random and kept in
  `dev/langfuse/.env` (git-ignored, mode 600).
- Traces are kept until you delete them.

Images are pinned by digest. To upgrade, change the tag and digest of `langfuse` and
`langfuse-worker` together.
