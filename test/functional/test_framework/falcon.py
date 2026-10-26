#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying COPYING file.
"""Independent compressed-Falcon parser for transaction encoding tests."""


def falcon512_alternates(signature):
    """Return negative-zero, unused-bit and combined encodings, or None.

    The input includes its final sighash byte. None means this canonical
    signature does not have both a zero coefficient and unused final bits.
    Malformed inputs raise instead of silently mutating an unrelated byte.
    """
    assert len(signature) > 42 and signature[0] == 0x39
    bits = ''.join(f'{b:08b}' for b in signature[41:-1])
    pos = 0
    zeros = []
    for _ in range(512):
        start = pos
        sign = int(bits[pos])
        magnitude = int(bits[pos + 1:pos + 8], 2)
        pos += 8
        while bits[pos] == '0':
            magnitude += 128
            assert magnitude <= 2047
            pos += 1
        pos += 1
        assert magnitude or not sign
        if magnitude == 0:
            zeros.append(start)
    assert 0 <= len(bits) - pos < 8
    assert '1' not in bits[pos:]
    if not zeros or pos == len(bits):
        return None
    negative_zero = bytearray(signature)
    negative_zero[41 + zeros[0] // 8] |= 1 << (7 - zeros[0] % 8)
    tail = bytearray(signature)
    tail[-2] |= 1
    both = bytearray(negative_zero)
    both[-2] |= 1
    return bytes(negative_zero), bytes(tail), bytes(both)
