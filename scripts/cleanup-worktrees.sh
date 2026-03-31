#!/usr/bin/env bash
# cleanup-worktrees.sh — Remove stale git worktrees that have no unmerged commits.
#
# Usage:
#   ./scripts/cleanup-worktrees.sh          # interactive (asks before removal)
#   ./scripts/cleanup-worktrees.sh --dry-run # list stale worktrees, remove nothing
#   ./scripts/cleanup-worktrees.sh --force   # remove all stale without prompting
#
# A worktree is considered "stale" if its branch has been fully merged into the
# current HEAD (i.e. git branch --merged includes it). Worktrees with unmerged
# commits are left untouched.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [[ -z "$REPO_ROOT" ]]; then
  echo "Error: not inside a git repository." >&2
  exit 1
fi

cd "$REPO_ROOT"

DRY_RUN=false
FORCE=false

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --force)   FORCE=true ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Usage: $0 [--dry-run] [--force]" >&2
      exit 1
      ;;
  esac
done

echo "==> Scanning worktrees in $REPO_ROOT/.claude/worktrees/ ..."
echo ""

# Build set of branches merged into HEAD
MERGED_BRANCHES=$(git branch --merged HEAD --format='%(refname:short)' 2>/dev/null || true)

STALE=()
UNMERGED=()
MISSING_PATH=()

# Iterate over all registered worktrees (skip the main one)
while IFS= read -r WT_LINE; do
  # git worktree list --porcelain output:
  # worktree /path
  # HEAD <sha>
  # branch refs/heads/<name>
  # (blank line between worktrees)
  true
done < <(git worktree list --porcelain)

# Parse worktree list
CURRENT_PATH=""
CURRENT_BRANCH=""
IS_MAIN=true

while IFS= read -r line; do
  if [[ "$line" == worktree\ * ]]; then
    # Process previous entry if any (skip the first "main" worktree)
    if [[ -n "$CURRENT_PATH" && "$IS_MAIN" == false ]]; then
      if [[ ! -d "$CURRENT_PATH" ]]; then
        MISSING_PATH+=("$CURRENT_PATH ($CURRENT_BRANCH)")
      elif echo "$MERGED_BRANCHES" | grep -qx "$CURRENT_BRANCH"; then
        STALE+=("$CURRENT_PATH|$CURRENT_BRANCH")
      else
        UNMERGED+=("$CURRENT_PATH ($CURRENT_BRANCH)")
      fi
    fi
    CURRENT_PATH="${line#worktree }"
    CURRENT_BRANCH=""
    IS_MAIN=false
  elif [[ "$line" == "branch refs/heads/"* ]]; then
    CURRENT_BRANCH="${line#branch refs/heads/}"
  elif [[ "$line" == "bare" || "$line" == "HEAD"* ]] && [[ "$IS_MAIN" == true ]]; then
    IS_MAIN=true
  fi
done < <(git worktree list --porcelain)

# Process the last entry
if [[ -n "$CURRENT_PATH" && "$IS_MAIN" == false ]]; then
  if [[ ! -d "$CURRENT_PATH" ]]; then
    MISSING_PATH+=("$CURRENT_PATH ($CURRENT_BRANCH)")
  elif echo "$MERGED_BRANCHES" | grep -qx "$CURRENT_BRANCH"; then
    STALE+=("$CURRENT_PATH|$CURRENT_BRANCH")
  else
    UNMERGED+=("$CURRENT_PATH ($CURRENT_BRANCH)")
  fi
fi

echo "── Results ─────────────────────────────────────────────────────────"
echo ""

if [[ ${#MISSING_PATH[@]} -gt 0 ]]; then
  echo "Missing paths (will be pruned automatically):"
  for wt in "${MISSING_PATH[@]}"; do
    echo "  - $wt"
  done
  echo ""
  git worktree prune
  echo "  => Pruned missing worktrees."
  echo ""
fi

if [[ ${#UNMERGED[@]} -gt 0 ]]; then
  echo "Worktrees with UNMERGED commits (skipped — review manually):"
  for wt in "${UNMERGED[@]}"; do
    echo "  - $wt"
  done
  echo ""
fi

if [[ ${#STALE[@]} -eq 0 ]]; then
  echo "No stale merged worktrees found. Nothing to clean up."
  exit 0
fi

echo "Stale worktrees (branch merged into HEAD, safe to remove):"
for entry in "${STALE[@]}"; do
  WT_PATH="${entry%%|*}"
  WT_BRANCH="${entry##*|}"
  echo "  - $WT_PATH  [branch: $WT_branch]"
done
echo ""

if [[ "$DRY_RUN" == true ]]; then
  echo "[dry-run] No changes made."
  exit 0
fi

REMOVED=0
for entry in "${STALE[@]}"; do
  WT_PATH="${entry%%|*}"
  WT_BRANCH="${entry##*|}"

  if [[ "$FORCE" == false ]]; then
    read -r -p "Remove worktree '$WT_PATH' (branch: $WT_BRANCH)? [y/N] " REPLY
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
      echo "  Skipped."
      continue
    fi
  fi

  git worktree remove --force "$WT_PATH" 2>/dev/null || true
  git branch -d "$WT_BRANCH" 2>/dev/null || true
  echo "  Removed: $WT_PATH"
  REMOVED=$((REMOVED + 1))
done

echo ""
echo "Done. Removed $REMOVED stale worktree(s)."
