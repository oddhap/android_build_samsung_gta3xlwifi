#!/usr/bin/env bash
set -euo pipefail
p=/srv/android/ports/lineage-24.0-arm64
a=/srv/android/artifacts/lineage-24.0-arm64
l=/srv/android/logs/lineage-24.0-arm64
label=java-permission-collector-validation-20261114-01
exec >"$l/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$l/$label.exit"; date -u' EXIT
python3 "$p/lineage-24.0/tools/compile-permission-collector24.py" --top /srv/android/src/lineage-24.0-arm64 --source "$p/java-permission-collector24-20261114-02" --client-report "$a/policy-client-native-20261114-03/report.json" --permission-report "$a/permission-install-identity-native-20261114-01/report.json" --snapshot "$p/lineage-24.0/snapshots/port-20261106-04" --output "$a/java-permission-collector-native-20261114-02"
python3 "$p/lineage-24.0/tools/test-permission-collector24.py" --top /srv/android/src/lineage-24.0-arm64 --source "$p/java-permission-collector24-20261114-02" --native-report "$a/java-permission-collector-native-20261114-02/report.json" --permission-report "$a/permission-install-identity-native-20261114-01/report.json" --output "$a/java-permission-collector-host-20261114-01"
