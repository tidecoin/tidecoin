# Mempool Limits

## Dependencies and clusters

If transaction Tx1 spends an output of Tx0, Tx0 is a *parent* of Tx1 and Tx1 is
its *child*. Ancestors and descendants include these relationships recursively.
The ancestor and descendant counts and sizes reported by mempool RPCs include
the transaction itself.

A *cluster* is a connected component of unconfirmed transactions: any two entries
in it are connected by parent/child relationships, in either direction. A
transaction spending outputs from two separate clusters joins those clusters.
A cluster can therefore be larger than any individual entry's ancestor or
descendant set.

By default, every cluster is limited to:

- 64 transactions (`-limitclustercount=64`).
- 968,000 sigop-adjusted weight units (`-limitclustersize=242`, in decimal
  thousands of virtual bytes).

The size check sums exact adjusted weights. It does not sum individually rounded
virtual sizes displayed by RPCs. Adjustment accounts for signature-operation cost
as well as transaction weight. The supported configuration ranges are 1–64
transactions and 1–242 thousand virtual bytes; nodes may choose smaller limits.

These are local admission and retention rules, not consensus limits. A valid
block may contain a group that a node would reject from its mempool. Different
versions or configurations can consequently relay different unconfirmed groups
while accepting the same valid blocks.

## Admission, replacement and CPFP

An addition must leave every resulting cluster within both limits. Small chains
can exceed the former 25-entry ancestor limit, but wide or interleaved dependency
graphs previously admitted under separate ancestry limits may now be rejected.
Ordinary payments and consolidations remain subject to the separate standard
transaction weight limit of 800,000 WU.

A replacement is checked against the graph after staging removal of its conflicts
and their descendants. Rejection discards the staged changes. There is no separate
single-conflict RBF limit discount. Replacement must also satisfy the fee and work
rules described in [mempool replacements](mempool-replacements.md).

A child paying for its parent must fit the same cluster limits. The former CPFP
carve-out is removed: there is no extra transaction or size allowance beyond a
full cluster. The default 242,000-vbyte-equivalent limit accommodates the former
202,000-vbyte descendant allowance plus its 40,000-vbyte CPFP exception, but this
does not preserve every previously accepted dependency graph.

Package submission has its own limits: at most 25 transactions and 808,000 WU.
It does not allow bypassing cluster limits. TRUC transactions retain their
separate 2-ancestor/2-descendant, 10,000-vbyte transaction and 4,000-vbyte child
restrictions. See [packages](packages.md) for package acceptance details.

## Compatibility options and memory budget

`-limitancestorcount` and `-limitdescendantcount` remain wallet selection
preferences; they no longer configure mempool admission. `-limitancestorsize`
and `-limitdescendantsize` are ignored with a warning. Use the cluster options to
configure admission limits.

A nonzero `-maxmempool` budget must be at least 40 times the configured cluster
size in virtual bytes. With default cluster limits this requires at least 10 MB
when expressed as an integer command-line value. The blocks-only default is also
10 MB. Explicit `-maxmempool=0` is supported, but does not retain unconfirmed
transactions. Memory-pressure eviction can remove entries even when their
clusters satisfy the topology and size limits.
