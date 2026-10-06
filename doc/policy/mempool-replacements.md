# Mempool Replacements

## Current Replace-by-Fee Policy

A transaction conflicts with an in-mempool transaction ("directly conflicting transaction") if they
spend one or more of the same inputs. A transaction may conflict with multiple in-mempool
transactions.

A transaction ("replacement transaction") may replace its directly conflicting transactions and
their in-mempool descendants (together, "original transactions") if, in addition to passing all
other consensus and policy rules, each of the following conditions are met:

1. (Removed)

2. (Removed)

3. The replacement transaction pays an absolute fee of at least the sum paid by the original
   transactions.

   *Rationale*: Only requiring the replacement transaction to have a higher feerate could allow an
   attacker to bypass node minimum relay feerate requirements and cause the network to repeatedly
   relay slightly smaller replacement transactions without adding any more fees. Additionally, if
   any of the original transactions would be included in the next block assembled by an economically
   rational miner, a replacement policy allowing the replacement transaction to decrease the absolute
   fees in the next block would be incentive-incompatible.

4. The additional fees (difference between absolute fee paid by the replacement transaction and the
   sum paid by the original transactions) pays for the replacement transaction's bandwidth at or
   above the rate set by the node's incremental relay feerate. For example, if the incremental relay
   feerate is 0.1 satoshi/vB and the replacement transaction is 500 virtual bytes total, then the
   replacement pays a fee at least 50 satoshis higher than the sum of the original transactions.

   *Rationale*: Try to prevent DoS attacks where an attacker causes the network to repeatedly relay
   transactions each paying a tiny additional amount in fees, e.g. just 1 satoshi.

5. At most 100 distinct clusters may contain directly conflicting transactions. Tidecoin also
   limits the union of transactions actually removed (direct conflicts and their descendants) to
   100 entries. Shared descendants count once.

   *Rationale*: Bound dependency processing and the amount of mempool state removed by one
   replacement. The additional removal bound is stricter than Bitcoin's cluster-only bound.

6. The replacement must strictly improve the affected mempool fee diagram. The comparison includes
   affected retained parents and descendants, not only directly conflicting transactions. Equal or
   crossing diagrams are rejected.

   *Rationale*: Compare the old and new sets using the same dependency-aware fee model used for
   block construction and eviction. This does not guarantee optimal block revenue when chunks do
   not fit the remaining block space.

7. The staged result must satisfy the cluster limits: by default at most 64 transactions and
   968,000 sigops-adjusted weight units (242,000 virtual-byte equivalent) in each connected
   component. Replacement removes the old conflicts before evaluating the resulting limits.

New unconfirmed inputs are permitted when these checks succeed. Spending an output of a transaction
being removed by the replacement remains prohibited. CPFP and RBF ancestor/descendant carveouts are
superseded by the staged cluster checks.

Local adjustments from `prioritisetransaction` retain signed 64-bit inputs and saturating updates.
Actual transaction fees determine coinbase revenue. Virtual priority adjustments are not additional
fees paid on chain. Relay ordering continues to use base fees, independently of local priority.

These are local mempool policies. A received consensus-valid block is not rejected for exceeding
mempool cluster limits or for containing a replacement this node would not have relayed. Older
Tidecoin peers can apply different unconfirmed-transaction limits and replacement policies.
