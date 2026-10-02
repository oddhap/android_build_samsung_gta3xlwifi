#!/usr/bin/env bash
set -euo pipefail
port_dir=$(cd "$(dirname "$0")/.." && pwd)
top_dir=${1:-/srv/android/src/lineage-21.0}
export PATH="$HOME/bin:$PATH"
mkdir -p "$top_dir"
cd "$top_dir"
if [[ -d .repo ]]; then
    echo 'Use an empty checkout for a pinned source sync; preserve existing builds.' >&2
    exit 1
fi
repo init --standalone-manifest -u "file://$port_dir/notes/pinned-build-manifest.xml" \
    --depth=1 --no-clone-bundle --git-lfs
repo sync -c -j8 --no-clone-bundle --no-tags --fail-fast
