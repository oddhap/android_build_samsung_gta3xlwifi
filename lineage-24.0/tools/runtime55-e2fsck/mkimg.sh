#!/bin/bash
# Synthetic ext4 image with Samsung-style v1 FBE contexts:
# directory ctx flags 0x00, file ctx flags 0x04 (CONFIG_EXT4_PRIVATE_ENCRYPTION),
# contents mode 127 (Exynos private), filenames mode 4 (AES-256-CTS).
set -e
B=$1; IMG=$2
rm -f $IMG
$B/misc/mke2fs -q -t ext4 -O encrypt -b 4096 $IMG 16M
# 16-byte-plus "ciphertext-like" names so the name checks are satisfied
D=dddddddddddddddddddddddd
F1=ffffffffffffffffffffffff
F2=gggggggggggggggggggggggg
echo hello > /tmp/.e2t.$$
$B/debugfs/debugfs -w $IMG -f - >/dev/null <<CMDS
mkdir $D
cd $D
write /tmp/.e2t.$$ $F1
write /tmp/.e2t.$$ $F2
CMDS
rm -f /tmp/.e2t.$$
key=0123456789abcdef
nonce=00112233445566778899aabbccddeeff
dirctx="017f0400${key}${nonce}"
filectx="017f0404${key}${nonce}"
hex2file(){ echo -n "$1" | xxd -r -p > "$2"; }
hex2file $dirctx /tmp/.dctx.$$; hex2file $filectx /tmp/.fctx.$$
$B/debugfs/debugfs -w $IMG -f - <<CMDS
ea_set -f /tmp/.dctx.$$ /$D c
set_inode_field /$D flags 0x80800
ea_set -f /tmp/.fctx.$$ /$D/$F1 c
set_inode_field /$D/$F1 flags 0x80800
ea_set -f /tmp/.fctx.$$ /$D/$F2 c
set_inode_field /$D/$F2 flags 0x80800
CMDS
rm -f /tmp/.dctx.$$ /tmp/.fctx.$$
$B/debugfs/debugfs -R "ea_list /$D" $IMG
$B/debugfs/debugfs -R "ea_list /$D/$F1" $IMG
