# Physical boot reached SELinux but stopped during cgroup setup

Snapshot05 installed successfully (updater RC0,197s). Physical readbacks confirm
its static first-stage root link and exact executable hash, plus unchanged
boot/vendor/recovery identities. The actual new boot reaches first-stage init,
loads current SELinux policy and enters second stage. It then cannot mkdir /acct
on immutable system root. Real cpuacct setup fails and createProcessGroup prevents
ueventd and bootstrap apexd from starting, causing the requested reboot. The
optional vendor hw import is missing, but the actual flat vendor init file is
parsed from its existing location. No policy bypass or fake cgroup-ready result
is authorized. Snapshot06 adds only BOARD_ROOT_EXTRA_FOLDERS += acct and requires
that real directory/controller contract in the actual packaged target files.
