#!/bin/sh
set -eu

REPO_DIR="${REPO_DIR:-/notes}"
LOG_FILE="${LOG_FILE:-$REPO_DIR/.git/auto-sync.log}"
COMMIT_MESSAGE="${COMMIT_MESSAGE:-auto: notes}"
MAIN_BRANCH="${MAIN_BRANCH:-master}"
PUSH_BRANCH="${PUSH_BRANCH:-gwiki}"

export GIT_TERMINAL_PROMPT=0
export HOME="${HOME:-/home/gwiki}"
export GIT_CONFIG_GLOBAL="${GIT_CONFIG_GLOBAL:-$HOME/.gitconfig}"
export GIT_CREDENTIALS_FILE="${GIT_CREDENTIALS_FILE:-$HOME/.git-credentials}"

if [ ! -d "$REPO_DIR/.git" ]; then
  echo "auto-sync: no git repo in $REPO_DIR" >&2
  exit 1
fi

cd "$REPO_DIR"

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
exec >>"$LOG_FILE" 2>&1

echo "auto-sync: start $(date -Iseconds)"

git config --global credential.helper "store --file=$GIT_CREDENTIALS_FILE" >/dev/null 2>&1 || true

git checkout "$MAIN_BRANCH" || true

git add notes/ || true
if git diff --cached --quiet; then
  echo "auto-sync: no changes"
  exit 0
fi

git commit -m "$COMMIT_MESSAGE" || true

git push --force-with-lease origin HEAD:"$PUSH_BRANCH" || true

if ! git pull --rebase origin "$MAIN_BRANCH"; then
  git rebase --abort || true
  echo "auto-sync: rebase failed"
  tail -n 1000 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
  exit 0
fi

git push origin "$MAIN_BRANCH" || true

tail -n 1000 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
echo "auto-sync: done $(date -Iseconds)"
