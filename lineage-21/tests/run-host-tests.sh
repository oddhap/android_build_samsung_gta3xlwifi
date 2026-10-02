#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
result_dir=$(mktemp -d)
trap 'rm -rf "$result_dir"' EXIT
compiler=${CXX:-clang++}
extra_flags=()
if [[ $(uname) == Darwin ]]; then extra_flags+=(-DEREMOTEIO=121); fi
"$compiler" -std=c++17 -Wall -Wextra -Werror "${extra_flags[@]}" \
    -Itests/include -Icompat/netd compat/netd/Gta3xlwifiLegacyFirewall.cpp \
    tests/firewall-test.cpp -o "$result_dir/firewall-test"
"$result_dir/firewall-test"
"$compiler" -std=c++17 -Wall -Wextra -Werror \
    -include tests/include/stats-test-env.h -Itests/include -Icompat/networkstats \
    compat/networkstats/Gta3xlwifiLegacyStats.cpp tests/stats-test.cpp \
    -o "$result_dir/stats-test"
"$result_dir/stats-test"
