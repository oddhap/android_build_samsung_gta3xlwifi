#!/usr/bin/env python3
"""Fail closed when the secure-RPMB worker cannot open its block device."""
import sys
from pathlib import Path
root=Path(sys.argv[1]) if len(sys.argv)>1 else Path('/srv/android/src/kernel-gta3xlwifi')
p=root/'drivers/mmc/host/dw_mmc-srpmb.c'
s=p.read_text()
old='''		if (!bdev) {
			dev_err(dev, "Fail to get block device for mmc srpmb\\n");
			return -EINVAL;
		}'''
new='''		if (IS_ERR(bdev)) {
			ret = PTR_ERR(bdev);
			bdev = NULL;
			update_rpmb_status_flag(ctx, req, RPMB_INVALID_COMMAND);
			dev_err(dev, "Fail to get block device for mmc srpmb: %d\\n", ret);
			return ret;
		}'''
if new not in s:
    assert s.count(old)==1
    s=s.replace(old,new,1)
old='''		if (!fops->srpmb_access) {
			dev_err(dev, "No function pointer for srpmb access\\n");
			return -ENOTTY;
		}'''
new='''		if (!fops->srpmb_access || !fops->get_card) {
			dev_err(dev, "No function pointer for srpmb access\\n");
			blkdev_put(bdev, FMODE_READ | FMODE_WRITE);
			bdev = NULL;
			fops = NULL;
			update_rpmb_status_flag(ctx, req, RPMB_INVALID_COMMAND);
			return -ENOTTY;
		}'''
if new not in s:
    assert s.count(old)==1
    s=s.replace(old,new,1)
p.write_text(s)
