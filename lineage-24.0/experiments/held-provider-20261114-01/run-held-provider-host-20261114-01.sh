#!/usr/bin/env bash
set -euo pipefail
p=/srv/android/ports/lineage-24.0-arm64
a=/srv/android/artifacts/lineage-24.0-arm64
l=/srv/android/logs/lineage-24.0-arm64
s=$p/held-provider24-20261114-01
label=held-provider-host-validation-20261114-01
exec >"$l/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$l/$label.exit"; date -u' EXIT
flock -n "$l/build.lock" python3 "$p/lineage-24.0/tools/test-socket-tagger-transport24.py" --source "$s" --output "$a/held-provider-tagger-transport-host-20261114-01"
flock -n "$l/build.lock" python3 "$p/lineage-24.0/tools/test-held-provider-library24.py" --source "$s" --output "$a/held-provider-library-host-20261114-01"
flock -n "$l/build.lock" python3 "$p/lineage-24.0/tools/test-held-provider-owner24.py" --source "$s" --base-source "$p/socket-tagging-owner24-20261114-01" --reference-host "$a/socket-tagging-owner-host-20261114-03" --output "$a/held-provider-owner-host-20261114-01"
