#!/bin/bash
set -euo pipefail

# Only run in Claude Code on the web; locally the dev does this themselves.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

echo "[session-start] installing dependencies..."
npm ci

echo "[session-start] building site..."
npm run build

echo "[session-start] validating HTML..."
npm run validate:html

echo "[session-start] validating references..."
npm run validate:refs
