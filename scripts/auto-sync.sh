#!/bin/sh
set -eu

REPO_DIR="${REPO_DIR:-/notes}"
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

git config --global credential.helper "store --file=$GIT_CREDENTIALS_FILE" >/dev/null 2>&1 || true

git checkout "$MAIN_BRANCH" >/dev/null 2>&1 || true

git add notes/ >/dev/null 2>&1 || true
if git diff --cached --quiet; then
  exit 0
fi

git commit -m "$COMMIT_MESSAGE" >/dev/null 2>&1 || true

git push --force-with-lease origin HEAD:"$PUSH_BRANCH" >/dev/null 2>&1 || true

if ! git pull --rebase origin "$MAIN_BRANCH" >/dev/null 2>&1; then
  git rebase --abort >/dev/null 2>&1 || true
  exit 0
fi

git push origin "$MAIN_BRANCH" >/dev/null 2>&1 || true
