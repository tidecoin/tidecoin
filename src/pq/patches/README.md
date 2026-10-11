# PQClean Local Patch Inventory

This directory stores local patch snapshots for vendored PQClean components
listed in `src/pq/VERSIONS.toml`.

## Purpose
- Make local divergence from upstream explicit and reviewable.
- Give the deep vendor checker (`contrib/devtools/check_pq_vendor.py`) a
  stable patch artifact to validate against.

## Patch files
- `shared-fips202-cleanup.patch`
- `falcon-512-local-adaptations.patch`
- `falcon-1024-local-adaptations.patch`
- `ml-dsa-44-local-adaptations.patch`
- `ml-dsa-65-local-adaptations.patch`
- `ml-dsa-87-local-adaptations.patch`
- `ml-kem-512-local-adaptations.patch`

## Regeneration
From repository root, after updating vendored sources and `VERSIONS.toml`:

```bash
# Ensure /tmp/pqclean points to the pinned upstream commit.

{ for f in api.h inner.h pqclean.c; do
  diff -u --label "a/crypto_sign/falcon-512/clean/$f" \
          --label "b/src/pq/falcon-512/$f" \
          "/tmp/pqclean/crypto_sign/falcon-512/clean/$f" \
          "src/pq/falcon-512/$f" || true
done; } > src/pq/patches/falcon-512-local-adaptations.patch
```

Use the same pattern for each component listed above.
