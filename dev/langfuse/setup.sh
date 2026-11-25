#!/usr/bin/env bash
# Start the optional local Langfuse stack and point Secure Build at it.
#   ./setup.sh        start (first run: generate secrets, add LANGFUSE_* to the root .env)
#   ./setup.sh stop   stop the containers, keep the data
set -euo pipefail
cd "$(dirname "$0")"
root_env=../../.env

if [ "${1:-}" = stop ]; then
  exec docker compose stop
fi

if [ ! -f .env ]; then
  umask 077
  hex() { openssl rand -hex "$1"; }
  cat > .env <<ENV
POSTGRES_PASSWORD=$(hex 24)
CLICKHOUSE_PASSWORD=$(hex 24)
REDIS_PASSWORD=$(hex 24)
MINIO_PASSWORD=$(hex 24)
SALT=$(hex 32)
ENCRYPTION_KEY=$(hex 32)
NEXTAUTH_SECRET=$(hex 32)
LANGFUSE_PUBLIC_KEY=pk-lf-$(hex 16)
LANGFUSE_SECRET_KEY=sk-lf-$(hex 24)
ADMIN_EMAIL=admin@secure-build.local
ADMIN_PASSWORD=$(hex 12)Aa1!
ENV
  echo "Generated secrets in dev/langfuse/.env (git-ignored)."
fi

docker compose up -d

printf 'Waiting for Langfuse'
for _ in $(seq 1 90); do
  if curl -fsS -o /dev/null http://localhost:3200/api/public/health 2>/dev/null; then ready=1; break; fi
  printf .; sleep 2
done
echo
[ "${ready:-}" = 1 ] || { echo "Langfuse did not become healthy; see: docker compose logs langfuse-web" >&2; exit 1; }

if [ -f "$root_env" ] && grep -q '^LANGFUSE_HOST=' "$root_env"; then
  echo "The root .env already sets LANGFUSE_HOST; left unchanged."
else
  {
    printf '\n# --- Langfuse tracing (optional; dev/langfuse). Remove LANGFUSE_HOST to turn it off ---\n'
    echo 'LANGFUSE_HOST=http://localhost:3200'
    grep -E '^LANGFUSE_(PUBLIC|SECRET)_KEY=' .env
  } >> "$root_env"
  echo "Added LANGFUSE_* to the root .env; restart the backend to use it."
fi
echo "Langfuse: http://localhost:3200 (sign-in: ADMIN_EMAIL / ADMIN_PASSWORD in dev/langfuse/.env)"
