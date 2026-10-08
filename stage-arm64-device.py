#!/usr/bin/env python3
"""Configure the isolated multilib product and stage exact reviewed inputs."""
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path('/srv/android')
DEVICE = ROOT/'src/lineage-21.0-arm64/device/samsung/gta3xlwifi'
OUT = ROOT/'artifacts/lineage-21-arm64'
def change(path, old, new):
    text = path.read_text()
    if new in text:
        return
    if old in text:
        if text.count(old) != 1: raise SystemExit(f'Ambiguous edit: {path}')
        path.write_text(text.replace(old, new))
    else:
        raise SystemExit(f'Unexpected source: {path}')

change(DEVICE/'BoardConfig.mk', '# The stock vendor ABI is 32-bit; the separately compiled kernel is ARM64.\nTARGET_ARCH := arm\nTARGET_ARCH_VARIANT := armv8-a\nTARGET_CPU_ABI := armeabi-v7a\nTARGET_CPU_ABI2 := armeabi\nTARGET_CPU_VARIANT := generic\nTARGET_CPU_VARIANT_RUNTIME := cortex-a53', '# Mixed ARM64/ARM32 userspace, with retained ARM32 Samsung HAL services.\nTARGET_ARCH := arm64\nTARGET_ARCH_VARIANT := armv8-a\nTARGET_CPU_ABI := arm64-v8a\nTARGET_CPU_VARIANT := generic\nTARGET_CPU_VARIANT_RUNTIME := cortex-a53\nTARGET_2ND_ARCH := arm\nTARGET_2ND_ARCH_VARIANT := armv8-a\nTARGET_2ND_CPU_ABI := armeabi-v7a\nTARGET_2ND_CPU_ABI2 := armeabi\nTARGET_2ND_CPU_VARIANT := generic\nTARGET_2ND_CPU_VARIANT_RUNTIME := cortex-a53')
change(DEVICE/'lineage_gta3xlwifi.mk', '$(call inherit-product, $(SRC_TARGET_DIR)/product/full_base.mk)', '$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)\n$(call inherit-product, $(SRC_TARGET_DIR)/product/full_base.mk)')
# The fixed 312 MiB product partition cannot hold the dual-ABI WebView APK.
# This supported Make override preserves WebView and both ABIs on system.
webview_layout = '''\n# Dual-ABI WebView exceeds the fixed product partition; system has headroom.
PRODUCT_FORCE_PRODUCT_MODULES_TO_SYSTEM_PARTITION += webview
'''
device_mk = DEVICE/'device.mk'
if 'PRODUCT_FORCE_PRODUCT_MODULES_TO_SYSTEM_PARTITION += webview' not in device_mk.read_text():
    with device_mk.open('a') as stream:
        stream.write(webview_layout)
# Init prefers product ABI declarations over the retained ARM32 ODM declarations.
product_abi = '''\n# Declare the complete userspace ABI list ahead of Samsung's ARM32 ODM metadata.
PRODUCT_PRODUCT_PROPERTIES += \\
    ro.product.product.cpu.abilist=arm64-v8a,armeabi-v7a,armeabi \\
    ro.product.product.cpu.abilist64=arm64-v8a \\
    ro.product.product.cpu.abilist32=armeabi-v7a,armeabi
'''
if 'ro.product.product.cpu.abilist=arm64-v8a,armeabi-v7a,armeabi' not in device_mk.read_text():
    with device_mk.open('a') as stream:
        stream.write(product_abi)
product_mk = DEVICE/'lineage_gta3xlwifi.mk'
inherit64 = '$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)\n'
text = product_mk.read_text()
while inherit64 + inherit64 in text:
    text = text.replace(inherit64 + inherit64, inherit64)
product_mk.write_text(text)
crypto = '''# SPDX-License-Identifier: Apache-2.0
# Regular device init file: Android 14 init uses O_NOFOLLOW for imports.
# Preserve genuine platform/APEX self-tests for both supported ABIs.
on init && property:ro.product.cpu.abilist32=*
    exec_start boringssl_self_test32

on init && property:ro.product.cpu.abilist64=*
    exec_start boringssl_self_test64

on property:apexd.status=ready && property:ro.product.cpu.abilist32=*
    exec_start boringssl_self_test_apex32

on property:apexd.status=ready && property:ro.product.cpu.abilist64=*
    exec_start boringssl_self_test_apex64
'''
(DEVICE/'rootdir/init.gta3xlwifi.crypto.rc').write_text(crypto)
prebuilt = DEVICE/'prebuilt'
prebuilt.mkdir(exist_ok=True)
for name in ('Image', 'dtbo.img'):
    shutil.copy2(OUT/'baseline-inputs'/name, prebuilt/name)
report = json.loads((OUT/'vendor-image-report.json').read_text())
vendor = OUT/'vendor-hybrid-arm64.img'
if hashlib.sha256(vendor.read_bytes()).hexdigest() != report['sparse_sha256']:
    raise SystemExit('Hybrid vendor checksum differs from the inspected image')
shutil.copy2(vendor, prebuilt/'vendor.img')
# Build-time metadata remains identical to the original vendor policy/VINTF.
# ARM64 additions and property changes are in the actual prebuilt image.
source = ROOT/'src/lineage-21.0/device/samsung/gta3xlwifi/configs'
shutil.copytree(source/'stock', DEVICE/'configs/stock', dirs_exist_ok=True)
shutil.copy2(source/'vendor-metadata.mk', DEVICE/'configs/vendor-metadata.mk')
provenance = {'architecture': 'arm64+arm', 'stock_firmware': 'T510XXU5CWA1/T510OXM5CVG2', 'donor_firmware': 'SM-A305GT A305GTVJU8CWE1 ZTO', 'kernel_sha256': hashlib.sha256((prebuilt/'Image').read_bytes()).hexdigest(), 'dtbo_sha256': hashlib.sha256((prebuilt/'dtbo.img').read_bytes()).hexdigest(), 'vendor_sha256': report['sparse_sha256'], 'hardware_tested': False, 'google_apps_added': False}
(prebuilt/'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
print(json.dumps(provenance, indent=2))
