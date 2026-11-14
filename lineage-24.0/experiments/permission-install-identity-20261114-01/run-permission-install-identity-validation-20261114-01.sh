#!/usr/bin/env bash
set -euo pipefail
p=/srv/android/ports/lineage-24.0-arm64
a=/srv/android/artifacts/lineage-24.0-arm64
l=/srv/android/logs/lineage-24.0-arm64
label=permission-install-identity-validation-20261114-01
exec >"$l/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$l/$label.exit"; date -u' EXIT
flock -n "$l/build.lock" python3 "$p/lineage-24.0/tools/test-permission-lifecycle24.py" --top /srv/android/src/lineage-24.0-arm64 --source "$p/permission-install-identity24-20261114-01" --native-report "$a/permission-install-identity-native-20261114-01/report.json" --output "$a/permission-install-identity-lifecycle-host-20261114-01"
python3 "$p/lineage-24.0/tools/check-permission-snapshot-api24.py" --top /srv/android/src/lineage-24.0-arm64 --source "$p/permission-install-identity24-20261114-01" --native-report "$a/permission-install-identity-native-20261114-01/report.json" --output "$a/permission-install-identity-api-20261114-01"
