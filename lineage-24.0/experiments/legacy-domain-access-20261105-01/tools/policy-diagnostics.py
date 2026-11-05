#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Split strict secilc diagnostics without losing extended-permission failures."""
import re

MARKER = re.compile(r'^(neverallow(?:xperm|x)?) check failed at (.+)\n', re.MULTILINE)


def blocks(log):
    matches = list(MARKER.finditer(log))
    result = []
    for i, match in enumerate(matches):
        end = matches[i+1].start() if i+1 < len(matches) else len(log)
        body = log[match.end():end]
        assertion = next((s.strip() for s in body.splitlines()
                          if s.strip().startswith('('+match.group(1)+' ')), None)
        if not assertion:
            raise ValueError('Missing assertion for '+match.group(0).strip())
        result.append({'kind':match.group(1), 'location':match.group(2),
                       'assertion':assertion, 'body':body})
    return result
