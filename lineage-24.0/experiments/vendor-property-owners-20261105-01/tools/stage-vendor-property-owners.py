#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Classify a reviewed set of vendor-namespaced properties as vendor restricted.

Uses actual vendor context names and a bound direct-writer inventory. No public
scope fallback or new allow. Adds the current vendor_restricted_prop writer
assertion, including init's exception, expressed using the legacy public API.
Effective permissions, runtime readers/writers and property values are not proved.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

REVIEWED = '''vendor_bssl_post_prop vendor_camera_prop vendor_config_default_prop
vendor_debug_egl_prop vendor_device_prop vendor_display_sf_prop vendor_dolby_prop
vendor_dumpstate_config_prop vendor_eden_prop vendor_heimdalld_prop vendor_members_prop
vendor_mobicoredaemon_prop vendor_nfc_prop vendor_persist_config_default_prop
vendor_persist_sys_default_prop vendor_proxydaemon_prop vendor_radio_prop vendor_rild_prop
vendor_ro_config_default_prop vendor_ro_sys_default_prop vendor_sec_camera_prop
vendor_sec_cass_prop vendor_sec_vaultkeeper_prop vendor_secureos_prop vendor_sehal_init_prop
vendor_sys_default_prop vendor_teegris_prop vendor_tzdaemon_prop vendor_tztsdaemon_prop
vendor_wifi_ramdump_prop vendor_wifi_version vendor_wlbtd_prop'''.split()

p = argparse.ArgumentParser(description=__doc__)
for n in ['audit', 'baseline', 'output']:
    p.add_argument('--'+n, type=Path, required=True)
a = p.parse_args()
output = a.output.resolve()
assert not output.exists() and not output.is_relative_to(Path('/srv/android/src/lineage-24.0-arm64'))
audit = json.loads(a.audit.read_text())
baseline = json.loads(a.baseline.read_text())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert audit['input_sha256'][str(a.baseline)] == sha(a.baseline)
for path, expected in audit['input_sha256'].items():
    assert sha(Path(path)) == expected
for item in baseline['inputs']:
    assert audit['input_sha256'][item['path']] == item['sha256'] == sha(Path(item['path']))
vendors = [Path(x['path']) for x in baseline['inputs'] if Path(x['path']).name == 'vendor_sepolicy.cil']
assert len(vendors) == 1
vendor = vendors[0]
assert not output.is_relative_to(vendor.parent)
rows = {x['type']: x for x in audit['rows']}
selected = []
for name in sorted(REVIEWED):
    row = rows[name]
    assert not row['direct_owner_memberships']
    assert row['context_namespace'] == 'vendor_prefixes_only' and row['contexts']
    assert not row['direct_known_core_or_broad_writer_symbols']
    selected.append(row)
assert len(set(REVIEWED)) == 32
original = vendor.read_text()
group, noninit = 'vendor_samsung_port_restricted_properties', 'vendor_samsung_port_noninit_core'
assert group not in original and noninit not in original
for item in baseline['inputs']:
    assert group not in Path(item['path']).read_text() and noninit not in Path(item['path']).read_text()
addition = '\n; Explicit Android17 owner/scope migration for reviewed vendor context labels.\n'
addition += f'(typeattribute {group})\n(typeattributeset {group} ('+' '.join(sorted(REVIEWED))+'))\n'
addition += f'(typeattributeset vendor_property_type ({group}))\n'
addition += f'(typeattributeset vendor_restricted_property_type ({group}))\n'
addition += f'(typeattribute {noninit})\n(typeattributeset {noninit} (and coredomain (not init_30_0)))\n'
addition += f'(neverallow {noninit} {group} (property_service (set)))\n'
spec = importlib.util.spec_from_file_location('cil', Path(__file__).with_name('stage-vendor-uwb-namespace.py'))
cil = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cil)
staged = original+addition
before, after = cil.rule_counts(original), cil.rule_counts(staged)
assert after == dict(before, neverallow=before['neverallow']+1)
output.mkdir(parents=True)
(output/'vendor_sepolicy.cil').write_text(staged)
(output/'added-owner-scope.cil').write_text(addition)
(output/'reviewed-properties.json').write_text(json.dumps(selected, indent=2)+'\n')
report = {'scope': __doc__, 'classified_types': sorted(REVIEWED), 'classified_count': 32,
          'scope_attribute': 'vendor_restricted_property_type', 'public_scope_assigned': False,
          'explicit_noninit_core_writer_assertion_added': True,
          'all_original_vendor_statements_byte_exact': staged.startswith(original),
          'vendor_rule_counts_before': before, 'vendor_rule_counts_after': after,
          'effective_permission_delta_proved': False, 'runtime_validated': False,
          'security_approved': False, 'flash_ready': False,
          'input_sha256': {str(a.audit):sha(a.audit),str(a.baseline):sha(a.baseline),str(vendor):sha(vendor)},
          'runner_sha256': sha(Path(__file__)), 'staged_vendor_sha256':sha(output/'vendor_sepolicy.cil')}
(output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
print('STAGED: 32 vendor-restricted property owners, no public fallback, one added writer assertion')
