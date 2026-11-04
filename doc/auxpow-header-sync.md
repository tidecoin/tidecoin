# AuxPoW header synchronization

An AuxPoW header includes the child header and its parent proof. Its size varies
with the proof. Tidecoin therefore limits a P2P `headers` reply by both count and
bytes. Implementations exchanging AuxPoW headers must use the same continuation
rule; a short reply by count does not necessarily mean the peer has reached its
tip.

## Reply size and continuation

The count ceiling is 2,000 headers. The byte threshold is **6,000,000 bytes** of
the complete canonical `headers` payload:

```text
CompactSize(header_count) + sum(serialized_header_size + 1)
```

Each added byte is the zero transaction count following that header. Append a
complete header, then stop when either ceiling is reached, the requested stop
hash is reached, or the chain ends. A receiver requests more when the original
batch reaches either ceiling. This applies to ordinary synchronization and both
passes of low-work header synchronization. Measure the received batch before
discarding its proofs or releasing buffered headers. An empty reply ends the
exchange; a final byte-full reply can require one extra request to discover the
chain end.

A complete AuxPoW header cannot exceed 1,500,000 bytes under the current block
weight limit. That is a necessary condition, not a guarantee that a whole block
containing it is valid. Appending one final header after a payload below the
threshold keeps replies below the **8,000,000-byte** message ceiling. Outgoing
messages over that ceiling are refused and the connection is closed.

Header announcements fall back to a block inventory announcement when their
combined size reaches or exceeds the threshold or a required proof is
unavailable. The peer can then request headers or blocks through the normal
exchange.

This rule applies without a protocol-version gate. Ordinary 80-byte headers
reach the count ceiling first. Older count-only implementations may stop early
on large-proof chains and must be updated. Supporting older release-candidate
binaries on those chains is outside the coordinated deployment scope.

## Availability and pruning

Ordinary headers can be reconstructed from the block index. AuxPoW proofs are
read from retained block files, using bounded prefix reads without loading the
whole child block. Header-only entries do not retain their proofs, and pruning
removes proofs with the files containing them. There is no separate proof store.

For a known AuxPoW header whose proof is unavailable, `getblockheader` with
`verbose=false` returns RPC error `-1`. A file read, decode or child-hash mismatch
also returns `-1`. Verbose header metadata remains available from the index.
Binary and hex REST header requests return HTTP 404 for unavailable data or 500
for read failures; they do not return a partial successful response. JSON header
metadata does not require proof data.

If a `getheaders` range needs an unavailable proof, the serving node closes that
connection without penalizing the requester. It does not skip the header or
send an empty reply implying chain end. The requester needs another peer with
the data. If no peer retains it, this storage design cannot supply it.

The child block hash excludes the AuxPoW proof. Matching it checks the identity
of the child header, not proof integrity. Disk-header retrieval enforces record
and header-size boundaries but does not repeat full proof verification. P2P
receivers validate incoming proofs independently; proof-specific failures do
not permanently reject another valid proof for the same child hash. Repeated
serving from damaged storage can disrupt multiple peers. Raw RPC/REST read
success should not be interpreted as fresh proof verification.
