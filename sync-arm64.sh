#!/usr/bin/env bash
set -euo pipefail
top=/srv/android/src/lineage-21.0-arm64
port=/srv/android/ports/lineage-21-arm64/lineage-21
export PATH="$HOME/bin:$PATH"
mkdir -p "$top"
cd "$top"
if [[ ! -d .repo ]]; then
    repo init --standalone-manifest -u "file://$port/notes/pinned-build-manifest.xml" \
        --reference=/srv/android/src/lineage-21.0 \
        --depth=1 --no-clone-bundle --git-lfs
fi
repo sync -c -j8 --optimized-fetch --no-clone-bundle --no-tags --fail-fast
repo manifest -r -o /srv/android/artifacts/lineage-21-arm64/platform-manifest.xml
python3 "$port/tools/apply-pinned-patches.py" --top "$top" --check-only
python3 "$port/tools/apply-pinned-patches.py" --top "$top"
date -u +%FT%TZ > /srv/android/artifacts/lineage-21-arm64/SOURCE_SYNC_COMPLETE
