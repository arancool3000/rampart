#!/bin/zsh
# Serialised build for parallel agents: only one swift build runs at a time (shared incremental scratch).
# Usage: scripts/agent-build.sh [--product NAME]   (default product: RampartApp)
cd "$(dirname "$0")/.."
LOCK=.agent-build.lock
PRODUCT="${2:-RampartApp}"; [ "$1" = "--product" ] || PRODUCT="RampartApp"
for i in {1..900}; do mkdir "$LOCK" 2>/dev/null && break; sleep 2; done
trap 'rmdir "$LOCK" 2>/dev/null' EXIT
setopt pipefail
nice -n 10 swift build --scratch-path .build-agents --product "$PRODUCT" 2>&1 | grep -E "error:|Build complete" | head -30
