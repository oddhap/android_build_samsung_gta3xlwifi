# Raw socket UID xtables extensions

Adds two private revision0 builtin matches, `gta3xlwifi_raw_uid` and
`gta3xlwifi_raw_appid`, alongside the exact previous guard and lookup-appId
extensions. Mandatory numeric inclusive ranges use --raw_uid (uint32) and
--raw_appid (0..99999). Inversion is rejected. Print/save output retains an
explicit colon range, including singleton ranges. UAPI is byte-identical to the
actual isolated kernel build. Existing owner revision1 and registry are retained.

`xtables-raw-uid-native-20261106-01` passes actual Android17 compilation, real
registry generation, full archive and whole ARM64 iptables link. All70 original
registrations plus four private registration machine-code paths are verified.
Complete1,243-project/17-patch before/after source audits pass. No CLI parser,
kernel rule or packet execution is claimed. Native binaries stay on the server.
The patch is inactive and requires complete backend/hook/lifecycle integration.
