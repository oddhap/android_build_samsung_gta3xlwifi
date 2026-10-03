#!/usr/bin/env python3
"""Prepare a one-time certificate migration from a stopped Android packages.xml.

Input/output contain private app inventory and must never be committed. Only
certificate and key-set values matching the supplied old certificates change.
Run abx2xml/xml2abx on Android 12+; retain the original ABX file for rollback.
"""
import argparse
from collections import Counter
import copy
import json
from pathlib import Path
import subprocess
from xml.etree import ElementTree as ET

parser = argparse.ArgumentParser()
parser.add_argument('packages_xml', type=Path)
parser.add_argument('certificate_map', type=Path)
parser.add_argument('output_xml', type=Path)
parser.add_argument('--report', type=Path, required=True)
args = parser.parse_args()
mapping = json.loads(args.certificate_map.read_text())
certs, keys = {}, {}

def public_key(der):
    pem = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-pubkey', '-noout'],
                         input=bytes.fromhex(der), capture_output=True, check=True).stdout
    return ''.join(line.decode() for line in pem.splitlines() if not line.startswith(b'---'))

for item in mapping:
    old, new = item['old_cert'], item['new_cert']
    if old in certs and certs[old] != new:
        raise SystemExit('Ambiguous certificate migration')
    certs[old] = new
    old_key, new_key = public_key(old), public_key(new)
    if old_key in keys and keys[old_key] != new_key:
        raise SystemExit('Ambiguous public-key migration')
    keys[old_key] = new_key

tree = ET.parse(args.packages_xml)
indices = {node.get('index'): node.get('key') for node in tree.iter('cert') if node.get('key')}
for package in tree.findall('package'):
    if package.get('codePath', '').startswith('/data/app/') and any(
            indices.get(cert.get('index')) in certs for cert in package.findall('sigs/cert')):
        raise SystemExit('A data APK uses an old system certificate; migrate its APK first: ' + package.get('name', ''))
original = copy.deepcopy(tree.getroot())
counts = Counter()
for node in tree.iter():
    if node.tag == 'cert' and node.get('key') in certs:
        node.set('key', certs[node.get('key')])
        counts['certificates_replaced'] += 1
    elif node.tag == 'public-key' and node.get('value') in keys:
        node.set('value', keys[node.get('value')])
        counts['public_keys_replaced'] += 1
if not counts['certificates_replaced']:
    raise SystemExit('No matching old certificates; refusing empty migration')
before, after = list(original.iter()), list(tree.iter())
for old, new in zip(before, after):
    if (old.tag, old.text, old.tail) != (new.tag, new.text, new.tail):
        raise SystemExit('Migration changed XML structure')
    expected = dict(old.attrib)
    if old.tag == 'cert' and old.get('key') in certs:
        expected['key'] = certs[old.get('key')]
    if old.tag == 'public-key' and old.get('value') in keys:
        expected['value'] = keys[old.get('value')]
    if expected != new.attrib:
        raise SystemExit('Migration changed an unrelated attribute')
assert len(before) == len(after)
tree.write(args.output_xml, encoding='utf-8', xml_declaration=True)
ET.parse(args.output_xml)
args.report.write_text(json.dumps({**counts, 'package_count': len(tree.findall('package')),
                                  'only_exact_certificate_and_keyset_values_changed': True,
                                  'wipes_data': False}, indent=2) + '\n')
print(args.report.read_text())
