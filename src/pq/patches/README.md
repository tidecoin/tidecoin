# Tidecoin PQ implementation change records

Tidecoin maintains the checked-in implementations under `src/pq/`. Those source
files are the source of truth and are compiled directly. These patches are
**generated records** of the changes from a preserved PQClean origin; they are
not applied by the normal build.

PQClean is [retired and archived read-only](https://github.com/PQClean/PQClean#readme).
The origin commit in `src/pq/VERSIONS.toml` records where the code came from. It
is not a moving update target. Tidecoin reviews implementation changes and their
compatibility requirements independently. Keep the original licenses and
attribution. No separate library repository is required for this workflow.

## Preserved origin

`src/pq/upstream/` contains a compressed snapshot of the required original files,
including each implementation's license and the shared files' license headers.
The manifest records its commit, selected paths and SHA-256 digest. See
[the snapshot notes](../upstream/README.md) for reproduction and origin checks.

Normal generation, reconstruction and CI checks use this checked-in snapshot
and do not access the network or require a PQClean checkout. `--no-fetch` also
forbids an initial clone during optional Git-origin verification.

## Editing and generation

1. Edit and test the maintained source files.
2. Update the component/patch metadata in `src/pq/VERSIONS.toml` when changing
   the recorded purpose, affected files or impact on Tidecoin's rules. An added
   or deleted component file must be explicitly recorded; the generator will
   not silently add it to the inventory.
3. Generate the patch records and inspect the diff:

   ```sh
   python3 contrib/devtools/check_pq_vendor.py --regenerate
   # Or regenerate one component:
   python3 contrib/devtools/check_pq_vendor.py --regenerate --component ml-dsa-44
   ```

4. Run the metadata, tool regression and reconstruction checks:

   ```sh
   python3 test/lint/lint-pq-vendor.py
   python3 contrib/devtools/test_pq_vendor.py
   python3 contrib/devtools/check_pq_vendor.py
   git diff --check
   ```

`--regenerate` writes only the selected patch files, then checks reconstruction.
It does not edit implementation files, select a new origin revision or update
manifest hashes. It validates all selected file inventories before writing any
patches. The ordinary checker is read-only apart from temporary directories.

Each changed file belongs to exactly one patch record. A component may reference
multiple records with disjoint file sets; they are applied in manifest order.
Overlapping file ownership is rejected: combine those changes into one record.
Git commits retain the development history, so these records need no intermediate
patch-stack states. Additions, deletions and binary files are supported.

Generated patches use consistent `a/src/pq/...` and `b/src/pq/...` paths. The
snapshot's original paths are mapped to those local paths through the manifest
before replay. Empty context lines are emitted without trailing spaces, as with
GNU diff's `--suppress-blank-empty` option. Source bytes are preserved.

## What the checker establishes

For every declared component, the checker verifies the snapshot digest, copies
its original files into a temporary tree, checks each patch's actual file list,
applies every patch, then compares the reconstructed files byte for byte with
the maintained source. It also rejects unrecorded additions/deletions, failed
hunks and patches that touch files outside their declared scope. Naming a file
in the manifest does not exempt its contents from comparison.

Algorithm component directories are checked in full except the two explicitly
ignored upstream Makefiles. The shared FIPS202 component explicitly selects
`fips202.c` and `fips202.h`; Tidecoin-native wrappers and adapters are maintained
directly and are not reconstructed from PQClean. The original snapshot retains
the upstream Makefiles even though Tidecoin uses its own build configuration.

Reconstruction proves that the recorded changes describe the checked-in source.
Implementation tests, compatibility tests and compiler checks establish its
behavior. A correct reconstruction does not replace those tests.
