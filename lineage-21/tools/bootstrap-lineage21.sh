#!/bin/bash
set -euo pipefail
ROOT=/srv/android
TOP="$ROOT/src/lineage-21.0"
export PATH="$HOME/bin:$PATH"
mkdir -p "$TOP" "$ROOT/artifacts/lineage-21" "$ROOT/logs"
cd "$TOP"
repo init -u https://github.com/LineageOS/android.git -b lineage-21.0 \
  --depth=1 --no-clone-bundle --git-lfs
repo sync -c -j8 --no-clone-bundle --no-tags --fail-fast
repo manifest -r -o "$ROOT/artifacts/lineage-21/lineage-21.0-source-manifest.xml"
git -C .repo/manifests rev-parse HEAD > "$ROOT/artifacts/lineage-21/manifest-revision.txt"
date -u +%FT%TZ > "$ROOT/artifacts/lineage-21/SOURCE_SYNC_COMPLETE"
