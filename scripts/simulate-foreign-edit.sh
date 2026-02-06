#!/usr/bin/env bash
set -euo pipefail

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "sqlite3 not found in PATH" >&2
  exit 1
fi

COOKIE="${GWIKI_SESSION_COOKIE:-}"
if [ -z "${COOKIE}" ]; then
  echo "Set GWIKI_SESSION_COOKIE to the gwiki_session cookie value." >&2
  echo "Example:" >&2
  echo "  export GWIKI_SESSION_COOKIE='gwiki_session=...'" >&2
  exit 1
fi

OWNER="${1:-tani}"
BASE_URL="${GWIKI_BASE_URL:-http://localhost:8080}"
DB_PATH="${GWIKI_DB_PATH:-./.wiki/index.sqlite}"

if [ ! -f "${DB_PATH}" ]; then
  echo "DB not found: ${DB_PATH}" >&2
  exit 1
fi

UID="$(sqlite3 "${DB_PATH}" "SELECT uid FROM files f JOIN users u ON u.id=f.user_id WHERE u.name='${OWNER}' AND uid IS NOT NULL AND uid != '' LIMIT 1;")"
if [ -z "${UID}" ]; then
  echo "No UID found for owner '${OWNER}'" >&2
  exit 1
fi

echo "Owner: ${OWNER}"
echo "UID: ${UID}"
echo "GET ${BASE_URL}/notes/${UID}/edit"

curl -v -H "Cookie: ${COOKIE}" "${BASE_URL}/notes/${UID}/edit"
