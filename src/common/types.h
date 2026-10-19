// Copyright (c) 2010-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! @file common/types.h is a home for simple enum and struct type definitions
//! that can be used internally by functions in the libbitcoin_common library,
//! but also used externally by node, wallet, and GUI code.
//!
//! This file is intended to define only simple types that do not have external
//! dependencies. More complicated types should be defined in dedicated header
//! files.

#ifndef BITCOIN_COMMON_TYPES_H
#define BITCOIN_COMMON_TYPES_H

#include <cstddef>
#include <optional>

namespace common {
enum class PSBTError {
    UTXO_MISMATCH,
    MISSING_INPUTS,
    MISSING_NON_WITNESS_UTXO,
    SIGHASH_MISMATCH,
    SIGHASH_UNSUPPORTED,
    SINGLE_WITHOUT_OUTPUT,
    MISSING_AMOUNT,
    MISSING_SPENT_AMOUNTS,
    PQHD_ORIGIN_MISMATCH,
    EXTERNAL_SIGNER_NOT_FOUND,
    EXTERNAL_SIGNER_FAILED,
    UNSUPPORTED,
    INCOMPLETE,
    OK,
};

struct PSBTInputError {
    size_t input;
    int requested_mode;
    std::optional<int> declared_mode;
    PSBTError error;
};
} // namespace common

#endif // BITCOIN_COMMON_TYPES_H
