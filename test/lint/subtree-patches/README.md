# Recorded subtree changes

`src/leveldb.patch` records the complete difference from the imported LevelDB
base tree `d14157fb2064132c65fef31feb2aba21d0aff025` (import record
`240a4fb95d5b843826081807019cd405aa654e2b`). The changes were introduced in
`999c2d385b` and `dbfc297e93`:

- Disable read-count-triggered compaction while retaining size/manual compaction,
  and align the existing read tests with that choice.
- Initialize compaction output size before an output-file open can fail, and
  verify failure accounting and recovery in the LevelDB tests.

No dependency source changes are made by recording this patch. Regenerate it
only after reviewing a deliberate source change or a new upstream base:

```sh
git diff --no-ext-diff --no-renames --full-index \
  d14157fb2064132c65fef31feb2aba21d0aff025 HEAD:src/leveldb \
  > test/lint/subtree-patches/src/leveldb.patch
```

The subtree check compares the complete committed delta byte for byte with the
recorded patch. It fails on extra, missing, or altered changes. Its optional
upstream comparison checks the unmodified imported base separately.
