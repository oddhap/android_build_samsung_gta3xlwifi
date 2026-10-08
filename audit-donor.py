#!/usr/bin/env python3
"""Static ELF dependency, symbol/version and namespace audit for ARM64 donor."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from elftools.elf.elffile import ELFFile

ROOT = Path('/srv/android')
DONOR = ROOT / 'vendor-donor/a305gt/vendor'
STOCK = ROOT / 'vendor-stock/extracted/vendor'
TOP = ROOT / 'src/lineage-21.0'
OUT = ROOT / 'artifacts/lineage-21-arm64'
VNDK = TOP / 'prebuilts/vndk/v30/arm64'

def inspect(path, root, domain):
    target = None
    physical = path
    if path.is_symlink():
        target = str(path.readlink())
        if target.startswith('/vendor/'):
            physical = root / target[len('/vendor/'):]
        else:
            physical = path.parent / target
        if not physical.is_file():
            return None
    with physical.open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            return None
        stream.seek(0)
        elf = ELFFile(stream)
        dynamic = elf.get_section_by_name('.dynamic')
        needed, soname, runpath = [], None, []
        if dynamic:
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED': needed.append(tag.needed)
                if tag.entry.d_tag == 'DT_SONAME': soname = tag.soname
                if tag.entry.d_tag in ('DT_RPATH', 'DT_RUNPATH'): runpath.append(str(tag))
        versions = {}
        for section_name in ('.gnu.version_r', '.gnu.version_d'):
            section = elf.get_section_by_name(section_name)
            if section:
                for version, auxiliaries in section.iter_versions():
                    for aux in auxiliaries:
                        index = aux.entry.get('vna_other', version.entry.get('vd_ndx'))
                        if index is not None: versions[index & 0x7fff] = aux.name
        symbols = elf.get_section_by_name('.dynsym')
        versym = elf.get_section_by_name('.gnu.version')
        exports, imports, weak = [], [], []
        if symbols:
            for i, symbol in enumerate(symbols.iter_symbols()):
                if not symbol.name or symbol['st_info']['bind'] == 'STB_LOCAL': continue
                vi = versym.get_symbol(i)['ndx'] if versym else 0
                version = versions.get(vi & 0x7fff) if isinstance(vi, int) else None
                name = symbol.name + ('@' + version if version else '')
                if symbol['st_shndx'] == 'SHN_UNDEF':
                    (weak if symbol['st_info']['bind'] == 'STB_WEAK' else imports).append(name)
                elif symbol['st_other']['visibility'] in ('STV_DEFAULT', 'STV_PROTECTED'):
                    exports.append(name)
    data = physical.read_bytes()
    strings = [s.decode('ascii', 'replace') for s in __import__('re').findall(rb'[\x20-\x7e]{8,}', data) if any(term in s for term in (b'r26p0', b'/vendor/', b'/dev/ion', b'/dev/mali', b'.so'))]
    return {'path': str(path), 'relative': str(path.relative_to(root)), 'domain': domain, 'symlink_target': target, 'elf_class': elf.elfclass, 'machine': elf['e_machine'], 'soname': soname, 'needed': needed, 'runpath': runpath, 'exports': sorted(set(exports)), 'imports': sorted(set(imports)), 'weak_imports': sorted(set(weak)), 'bytes': 0 if target else len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'relevant_strings': sorted(set(strings))}

parser = argparse.ArgumentParser()
parser.add_argument('--reuse-inventory', action='store_true', help='Recompute closure using the existing static ELF inventory')
args = parser.parse_args()
if args.reuse_inventory:
    cached = json.loads((OUT/'donor-inventory.json').read_text())
    inventory, platform = cached['vendor'], cached['platform_providers']
else:
    inventory = []
    for domain, root in [('donor', DONOR), ('stock', STOCK)]:
        for p in sorted(root.rglob('*')):
            if p.is_file() or p.is_symlink():
                record = inspect(p, root, domain)
                if record: inventory.append(record)
    platform = []
    for domain, root in [('vndk-sp', VNDK/'arch-arm64-armv8-a/shared/vndk-sp'), ('vndk-core', VNDK/'arch-arm64-armv8-a/shared/vndk-core'), ('bionic-sdk', TOP/'prebuilts/runtime/mainline/runtime/sdk/android/arm64/lib'), ('llndk-stub', TOP/'prebuilts/vndk/v34/arm64/arch-arm64-armv8-a/shared/llndk-stub')]:
        for p in sorted(root.glob('*.so')):
            record = inspect(p, root, domain)
            if record: platform.append(record)
byname = {}
for record in platform:
    key = record['soname'] or Path(record['path']).name
    # Actual bionic SDK exports take precedence over LLNDK stubs.
    byname.setdefault(key, record)
for record in inventory:
    if record['domain'] == 'donor' and record['elf_class'] == 64 and record['relative'].startswith('lib64/'):
        byname[Path(record['path']).name] = record
        if not record['symlink_target']:
            byname[record['soname'] or Path(record['path']).name] = record
seeds = ['lib64/egl/libGLES_mali.so', 'lib64/hw/gralloc.exynos7904.so', 'lib64/hw/gralloc.default.so', 'lib64/hw/android.hardware.graphics.mapper@2.0-impl.so', 'lib64/hw/memtrack.exynos7904.so', 'lib64/hw/android.hardware.renderscript@1.0-impl.so', 'lib64/hw/vulkan.universal7904.so', 'lib64/libMcClient.so', 'lib64/libOpenCL.so', 'bin/boringssl_self_test64', 'bin/snap_utility_64']
dynamic_loads = {'android.hardware.renderscript@1.0-impl.so': ['libRS_internal.so'], 'libRS_internal.so': ['libRSDriver.so'], 'libRSDriver.so': ['libRSCpuRef.so']}
roots = {r['relative']: r for r in inventory if r['domain'] == 'donor'}
closures = {}
selected = {}
for seed in seeds:
    if seed not in roots:
        closures[seed] = {'missing_seed': True, 'resolution': 'Retain stock ARM32 TEE; qualify libMcClient.so as 32 in vendor/etc/public.libraries.txt' if seed == 'lib64/libMcClient.so' else 'Unresolved'}
        continue
    queue, closure, missing = [roots[seed]], {}, []
    while queue:
        rec = queue.pop()
        if rec['path'] in closure: continue
        closure[rec['path']] = rec
        for name in rec['needed'] + dynamic_loads.get(Path(rec['path']).name, []):
            if name not in byname: missing.append({'requester': rec['relative'], 'needed': name})
            else: queue.append(byname[name])
    exports = {s for r in closure.values() for s in r['exports']}
    unversioned = {s.split('@')[0] for s in exports}
    unresolved = {}
    for r in closure.values():
        absent = [s for s in r['imports'] if (s not in exports if '@' in s else s not in unversioned)]
        if absent: unresolved[r['path']] = absent
    core = [r['relative'] for r in closure.values() if r['domain'] == 'vndk-core']
    closures[seed] = {'resolved_paths': sorted(closure), 'documented_dynamic_loads': dynamic_loads if 'renderscript' in seed else {}, 'missing_dependencies': missing, 'unresolved_strong_symbols': unresolved, 'vndk_core_in_closure': core, 'namespace_review_required': bool(core) and seed.startswith('lib64/'), 'sdk_or_stub_providers_require_final_build_check': True}
    selected.update({r['relative']: r for r in closure.values() if r['domain'] == 'donor'})
summary = {'vendor_elf_counts_including_aliases': dict(Counter(f"{r['domain']}:ELF{r['elf_class']}:{r['machine']}" for r in inventory)), 'selected_donor_files': {name: {'sha256': r['sha256'], 'bytes': r['bytes'], 'needed': r['needed'], 'symlink_target': r['symlink_target']} for name, r in sorted(selected.items())}, 'selected_donor_bytes': sum(r['bytes'] for r in selected.values()), 'whole_donor_lib64_bytes': sum(r['bytes'] for r in inventory if r['domain'] == 'donor' and r['relative'].startswith('lib64/')), 'physical_vendor_partition_bytes': 343932928, 'hardware_compatibility_proven': False}
OUT.mkdir(parents=True, exist_ok=True)
(OUT/'donor-inventory.json').write_text(json.dumps({'vendor': inventory, 'platform_providers': platform}, indent=2) + '\n')
(OUT/'dependency-closure.json').write_text(json.dumps(closures, indent=2) + '\n')
(OUT/'donor-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
for seed, report in closures.items():
    print(seed, 'missing:', report.get('missing_dependencies'), 'namespace_review:', report.get('namespace_review_required'), 'unresolved:', {Path(k).name: v for k,v in report.get('unresolved_strong_symbols', {}).items()})
