#!/usr/bin/env python3
# Copyright (c) 2026-present The Tidecoin developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""PQ-only process fixture. Holds public descriptors and prepared PSBT replies, never seeds."""
import argparse
import json
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--state', required=True)
parser.add_argument('--fingerprint')
parser.add_argument('--chain')
parser.add_argument('--stdin', action='store_true')
parser.add_argument('command', nargs='?')
parser.add_argument('--account')
parser.add_argument('--desc')
args = parser.parse_args()
state = json.loads(Path(args.state).read_text())
command = args.command
if args.stdin:
    command, psbt = sys.stdin.read().strip().split(' ', 1)
    Path(args.state + '.request').write_text(psbt)
with Path(args.state + '.calls').open('a') as calls:
    calls.write(command + '\n')
if command == 'enumerate':
    result = state.get('devices', [{'fingerprint': 'pq-fixture', 'model': 'PQ software fixture'}])
elif args.fingerprint != 'pq-fixture':
    result = {'error': 'Unexpected device selector'}
elif command == 'getdescriptors':
    result = state['descriptors']
elif command == 'displayaddress':
    result = {'address': state.get('display_override', state['addresses'].get(args.desc, 'unknown'))}
elif command == 'signtx':
    result = state.get('response', {'psbt': psbt, 'complete': True})
else:
    result = {'error': 'Unknown command'}
print(json.dumps(result))
