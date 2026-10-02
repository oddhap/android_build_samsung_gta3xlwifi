#!/bin/bash
set -euo pipefail
ROOT=/srv/android
mkdir -p "$HOME/bin" "$ROOT/src/lineage-19.1" "$ROOT/source-audit" "$ROOT/logs"
curl -fL https://storage.googleapis.com/git-repo-downloads/repo -o "$HOME/bin/repo"
chmod 755 "$HOME/bin/repo"
export PATH="$HOME/bin:$PATH"
export USE_CCACHE=1
export CCACHE_DIR="$ROOT/ccache"
ccache -M 40G
cd "$ROOT/src/lineage-19.1"
repo init -u https://github.com/LineageOS/android.git -b lineage-19.1 --depth=1 --no-clone-bundle --git-lfs
repo sync -c -j8 --no-clone-bundle --no-tags --fail-fast
repo manifest -r -o "$ROOT/artifacts/lineage-19.1-source-manifest.xml"
date -u +%FT%TZ > "$ROOT/artifacts/SOURCE_SYNC_COMPLETE"
