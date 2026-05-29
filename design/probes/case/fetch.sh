#!/usr/bin/env bash
# Re-fetch the CASE/UCO ontologies for the probe. Clones are gitignored;
# re-run this to repopulate. See FINDINGS.md for the analysis.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
git clone --depth 1 https://github.com/casework/CASE "$here/CASE"
git clone --depth 1 https://github.com/ucoProject/UCO "$here/UCO"
