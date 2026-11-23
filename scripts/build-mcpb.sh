#!/usr/bin/env bash
# Builds home-net-doctor-<version>.mcpb, the one-click Claude Desktop extension, from a clean copy
# that holds only what the server needs (no tests, no scripts) and production dependencies only.
set -euo pipefail
cd "$(dirname "$0")/.."
v=$(node -p 'require("./package.json").version')
m=$(node -p 'require("./manifest.json").version')
[ "$v" = "$m" ] || { echo "package.json ($v) and manifest.json ($m) versions differ"; exit 1; }
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp -r manifest.json package.json package-lock.json README.md LICENSE src assets "$stage"/
(cd "$stage" && npm ci --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error)
npx -y @anthropic-ai/mcpb@2.1.2 validate "$stage/manifest.json"
npx -y @anthropic-ai/mcpb@2.1.2 pack "$stage" "home-net-doctor-$v.mcpb"
