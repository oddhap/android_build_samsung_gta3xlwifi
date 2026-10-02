#!/bin/bash
set -euo pipefail
export PATH="$HOME/bin:$PATH"
mkdir -p /srv/android/src/twrp-12.1 /srv/android/artifacts /srv/android/logs
cd /srv/android/src/twrp-12.1
repo init --depth=1 --no-clone-bundle \
    -u https://github.com/minimal-manifest-twrp/platform_manifest_twrp_aosp.git \
    -b 6dc117d9cbd08430daa16db2013560e1c4017fa8
repo sync -c -j8 --no-clone-bundle --no-tags --fail-fast
repo manifest -r -o /srv/android/artifacts/twrp-12.1-source-manifest.xml
date -u +%FT%TZ > /srv/android/artifacts/TWRP_SOURCE_SYNC_COMPLETE
