#!/usr/bin/env bash
#
# install_hooks.sh - wires the SEC-003 pre-push hook into this repository via
# git's core.hooksPath, so pushes that would orphan a consumer pin fail fast.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(git -C "$SCRIPT_DIR/.." rev-parse --show-toplevel)"

if [ ! -x "$SCRIPT_DIR/githooks/pre-push" ]; then
	echo "error: $SCRIPT_DIR/githooks/pre-push missing or not executable" >&2
	exit 1
fi

git -C "$REPO" config core.hooksPath scripts/githooks

echo "installed SEC-003 pre-push hook for $REPO"
echo "  core.hooksPath = $(git -C "$REPO" config core.hooksPath)"
echo "uninstall with: git -C \"$REPO\" config --unset core.hooksPath"
