// Copyright (c) 2026 The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TIDECOIN_WALLET_TRANSACTIONPREVIEW_H
#define TIDECOIN_WALLET_TRANSACTIONPREVIEW_H

#include <consensus/amount.h>

#include <cstdint>

namespace wallet {
/** A read-only estimate for already selected inputs. Not a prepared transaction. */
struct TransactionPreview {
    int64_t weight{0};
    int64_t vsize{0};
    CAmount fee{0};
    CAmount change{0};
    bool insufficient_funds{false};
};
} // namespace wallet

#endif // TIDECOIN_WALLET_TRANSACTIONPREVIEW_H
