#!/usr/bin/env python3
"""Recheck selected donor imports against libraries from actual target-files.

VNDK 30 providers must match the audited prebuilts byte-for-byte. Bionic and
LLNDK providers are read from the packaged runtime APEX and system libraries.
This is a static ABI gate; device linker namespaces still require runtime tests.
"""
import argparse
import hashlib
import io
import json
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path
from elftools.elf.elffile import ELFFile

parser = argparse.ArgumentParser()
parser.add_argument('target_files', type=Path)
parser.add_argument('--artifacts', type=Path, default=Path('/srv/android/artifacts/lineage-21-arm64'))
parser.add_argument('--top', type=Path, default=Path('/srv/android/src/lineage-21.0-arm64'))
args = parser.parse_args()
inventory = json.loads((args.artifacts/'donor-inventory.json').read_text())
closures = json.loads((args.artifacts/'dependency-closure.json').read_text())
records = {record['path']: record for record in inventory['vendor'] + inventory['platform_providers']}
paths = {path for closure in closures.values() for path in closure.get('resolved_paths', [])}
report = {'hardware_tested': False, 'providers': {}, 'closures': {}}

def symbols(data):
    elf = ELFFile(io.BytesIO(data))
    assert elf.elfclass == 64 and elf['e_machine'] == 'EM_AARCH64'
    versions, defined_versions = {}, set()
    requirements = elf.get_section_by_name('.gnu.version_r')
    if requirements:
        for _, auxiliary in requirements.iter_versions():
            for aux in auxiliary:
                versions[aux['vna_other'] & 0x7fff] = aux.name
    definitions = elf.get_section_by_name('.gnu.version_d')
    if definitions:
        for definition, auxiliary in definitions.iter_versions():
            # Only the first Verdaux names this version; remaining entries
            # name its parents. Match Bionic's for_each_verdef implementation.
            aux = next(auxiliary)
            versions[definition['vd_ndx'] & 0x7fff] = aux.name
            if not definition['vd_flags'] & 1:  # VER_FLG_BASE
                defined_versions.add(aux.name)
    exports, global_exports, default_exports, imports, needed = set(), set(), set(), set(), []
    symtab = elf.get_section_by_name('.dynsym')
    versym = elf.get_section_by_name('.gnu.version')
    if symtab:
        for i, symbol in enumerate(symtab.iter_symbols()):
            if not symbol.name or symbol['st_info']['bind'] == 'STB_LOCAL':
                continue
            index = versym.get_symbol(i)['ndx'] if versym else 0
            version = versions.get(index & 0x7fff) if isinstance(index, int) else None
            name = symbol.name + ('@' + version if version else '')
            if symbol['st_shndx'] == 'SHN_UNDEF':
                if symbol['st_info']['bind'] != 'STB_WEAK':
                    imports.add(name)
            elif symbol['st_other']['visibility'] in ('STV_DEFAULT', 'STV_PROTECTED'):
                exports.add(name)
                if index == 'VER_NDX_GLOBAL' or isinstance(index, int) and index & 0x7fff == 1 or not versym:
                    global_exports.add(symbol.name)
                if not isinstance(index, int) or not index & 0x8000:
                    default_exports.add(symbol.name)
    dynamic = elf.get_section_by_name('.dynamic')
    if dynamic:
        needed = [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_NEEDED']
    return {'exports': exports, 'global_exports': global_exports,
            'default_exports': default_exports, 'defined_versions': defined_versions,
            'imports': imports, 'needed': needed}

def resolves(symbol, provider):
    name, separator, version = symbol.partition('@')
    if not separator:
        return name in provider['default_exports']
    if version in provider['defined_versions']:
        return symbol in provider['exports']
    # bionic/linker/linker.cpp:find_verdef_version_index returns kVersymGlobal
    # when the DSO lacks the requested definition. linker_soinfo.cpp then
    # accepts only global definitions (or a DSO with no versym table).
    return name in provider['global_exports']

actual = {}
with zipfile.ZipFile(args.target_files) as archive, tempfile.TemporaryDirectory(prefix='built-donor-', dir=args.artifacts) as temp:
    names = set(archive.namelist())
    payloads = {}
    def apex_file(apex, path):
        if apex not in payloads:
            matches = [name for name in names if name.endswith((f'/{apex}.apex', f'/{apex}.capex'))]
            assert len(matches) == 1, (apex, matches)
            package = zipfile.ZipFile(io.BytesIO(archive.read(matches[0])))
            if 'original_apex' in package.namelist():
                package = zipfile.ZipFile(io.BytesIO(package.read('original_apex')))
            image = Path(temp) / (apex + '.img')
            image.write_bytes(package.read('apex_payload.img'))
            payloads[apex] = image
        result = subprocess.run([str(args.top/'out/host/linux-x86/bin/debugfs_static'), '-R',
                                 'cat /' + path, str(payloads[apex])], capture_output=True, check=True)
        return result.stdout

    vendor_image = archive.read('IMAGES/vendor.img')
    vendor_report = json.loads((args.artifacts/'vendor-image-report.json').read_text())
    assert hashlib.sha256(vendor_image).hexdigest() == vendor_report['sparse_sha256']
    # The mounted hybrid was built and checked against this exact image.
    vendor = args.artifacts/'vendor-hybrid-mount'
    for path in sorted(paths):
        record = records[path]
        name = Path(path).name
        assert re.fullmatch(r'[A-Za-z0-9_.@+\-]+', name), name
        domain = record['domain']
        if domain == 'donor':
            relative = record['relative']
            if record['symlink_target']:
                relative = record['symlink_target'].removeprefix('/vendor/')
            data = (vendor/relative).read_bytes()
            location = 'VENDOR/' + relative
            assert hashlib.sha256(data).hexdigest() == record['sha256'], location
        elif domain in ('vndk-sp', 'vndk-core'):
            data = apex_file('com.android.vndk.v30', 'lib64/' + name)
            location = 'APEX/com.android.vndk.v30/lib64/' + name
            assert hashlib.sha256(data).hexdigest() == record['sha256'], location
        elif domain == 'bionic-sdk':
            data = apex_file('com.android.runtime', 'lib64/bionic/' + name)
            location = 'APEX/com.android.runtime/lib64/bionic/' + name
        elif domain == 'llndk-stub':
            location = 'SYSTEM/lib64/' + name
            data = archive.read(location)
        else:
            raise RuntimeError(domain)
        actual[path] = symbols(data)
        report['providers'][path] = {'packaged_path': location, 'domain': domain,
                                    'sha256': hashlib.sha256(data).hexdigest(),
                                    'needed': actual[path]['needed']}
    for seed, closure in closures.items():
        if closure.get('missing_seed'):
            assert seed == 'lib64/libMcClient.so'
            continue
        group = closure['resolved_paths']
        unresolved, global_version_fallbacks = {}, {}
        for path in group:
            # Runtime loader symbols and system-private LLNDK dependencies are
            # resolved by the built platform's own namespace, not by SP-HAL.
            if records[path]['domain'] not in ('donor', 'vndk-sp', 'vndk-core'):
                continue
            missing = []
            for symbol in sorted(actual[path]['imports']):
                providers = [candidate for candidate in group if resolves(symbol, actual[candidate])]
                if not providers:
                    missing.append(symbol)
                elif '@' in symbol and not any(symbol in actual[candidate]['exports'] for candidate in providers):
                    global_version_fallbacks[symbol] = providers
            if missing:
                unresolved[path] = sorted(missing)
        assert not unresolved, (seed, unresolved)
        if seed.startswith('lib64/'):
            assert not closure['vndk_core_in_closure'], seed
        report['closures'][seed] = {'unresolved_strong_symbols': unresolved,
                                    'bionic_global_version_fallbacks': global_version_fallbacks,
                                    'actual_packaged_providers_checked': True}
report['passed'] = True
(args.artifacts/'built-donor-abi-check.json').write_text(json.dumps(report, indent=2)+'\n')
print(f'Actual packaged ARM64 provider checks passed for {len(actual)} ELF files and {len(report["closures"])} closures.')
