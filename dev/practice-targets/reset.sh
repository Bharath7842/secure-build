#!/usr/bin/env bash
# Restore the practice targets to a known state: remove containers and the DVWA database
# volume, start fresh containers, then (re)create DVWA's database.
# FOR AUTHORIZED LOCAL TESTING ONLY — these targets are deliberately vulnerable.
set -euo pipefail

cd "$(dirname "$0")"

DVWA_URL="http://127.0.0.1:4280"
JUICE_URL="http://127.0.0.1:3001"

echo "Resetting practice targets (containers and the DVWA database volume)..."
docker compose down --volumes --remove-orphans
docker compose up --detach

wait_for() { # url, name
  local url="$1" name="$2"
  for _ in $(seq 1 60); do
    if curl -fsS -o /dev/null "$url"; then echo "  $name is up ($url)"; return 0; fi
    sleep 2
  done
  echo "  $name did not come up at $url within 120s" >&2
  return 1
}

wait_for "$JUICE_URL" "Juice Shop"
wait_for "$DVWA_URL/setup.php" "DVWA"

# DVWA starts with an empty database; "Create / Reset Database" on /setup.php fills it.
jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT
token="$(curl -fsS -c "$jar" -b "$jar" "$DVWA_URL/setup.php" | sed -n "s/.*name=['\"]user_token['\"] value=['\"]\([^'\"]*\)['\"].*/\1/p" | head -n1)"
if [ -z "$token" ]; then
  echo "  could not read DVWA's setup token; open $DVWA_URL/setup.php and click 'Create / Reset Database'" >&2
  exit 1
fi
curl -fsS -o /dev/null -c "$jar" -b "$jar" --data-urlencode "create_db=Create / Reset Database" \
  --data-urlencode "user_token=$token" "$DVWA_URL/setup.php"
echo "  DVWA database created. Log in at $DVWA_URL with admin / password."
echo "Done. Both targets are at their known initial state."
