#!/usr/bin/env bash
set -euo pipefail

mkdir -p repos outputs scripts

# 用法：
# 1) ./scripts/clone_repos.sh https://github.com/org/repo1.git https://github.com/org/repo2.git
# 2) REPO_LIST_FILE=repos.txt ./scripts/clone_repos.sh
# repos.txt 每行一个 git clone URL，支持 # 注释和空行

clone_one() {
  local url="$1"
  local name

  name="$(basename "${url%.git}")"
  if [[ -z "$name" || "$name" == "." || "$name" == "/" ]]; then
    echo "[skip] invalid repo url: $url"
    return 0
  fi

  if [[ -d "repos/$name/.git" || -d "repos/$name" ]]; then
    echo "[skip] repos/$name already exists"
    return 0
  fi

  echo "[clone] $url -> repos/$name"
  if ! git clone --depth 1 "$url" "repos/$name"; then
    echo "[warn] clone failed, continue: $url"
    rm -rf "repos/$name" || true
  fi
}

repos_from_file() {
  local file="$1"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(echo "$line" | xargs || true)"
    [[ -z "$line" ]] && continue
    clone_one "$line"
  done < "$file"
}

if [[ "$#" -gt 0 ]]; then
  for repo_url in "$@"; do
    clone_one "$repo_url"
  done
elif [[ -n "${REPO_LIST_FILE:-}" ]]; then
  if [[ ! -f "$REPO_LIST_FILE" ]]; then
    echo "[error] REPO_LIST_FILE not found: $REPO_LIST_FILE"
    exit 1
  fi
  repos_from_file "$REPO_LIST_FILE"
else
  echo "[info] no repositories provided; pass URLs as args or set REPO_LIST_FILE"
fi
