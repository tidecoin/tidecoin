// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <test/util/script.h>

bool IsValidFlagCombination(unsigned flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

unsigned ScriptFlagsForComparison(unsigned flags, unsigned requested_changes, bool success)
{
    requested_changes &= ~(SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512 | SCRIPT_VERIFY_SHA512);
    return success ? flags & ~requested_changes : flags | requested_changes;
}
