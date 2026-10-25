# Preserved PQClean origin

Tidecoin maintains its own PQ source. This directory preserves the relevant
original files from PQClean commit
`3730b32aa50ba9e712592c1476bdd048f5f6ed7e`, so reconstructing our source does not
depend on the continued availability of the archived repository.

The snapshot contains 120 original files: the six clean implementation
directories, the two shared FIPS202 files, `common/compat.h`, and PQClean's README. It includes the
implementation licenses and upstream Makefiles. It contains no Tidecoin changes.
The checked-in archive's SHA-256 digest and selection paths are recorded in
`../VERSIONS.toml`. Original per-file license terms still apply.

The compatibility header is preserved so its Clang version-macro correction is
also reconstructed. Its original contents match Tidecoin's imported header
exactly. Adding it does not change the origin revision or any of the other
119 original files.

Ordinary checks need no Git-origin cache and use no network:

```sh
python3 contrib/devtools/check_pq_vendor.py
```

To independently compare every preserved file and the selected file set with
an existing PQClean Git repository:

```sh
python3 contrib/devtools/check_pq_vendor.py --verify-upstream \
  --upstream-repo /path/to/PQClean --no-fetch
```

Alternatively, `--verify-upstream --cache-dir /path/to/cache` permits obtaining
missing Git objects from the recorded origin. With `--no-fetch`, a missing cache
or commit is an error; no clone or fetch is attempted. A checkout's working-tree
changes are irrelevant because verification reads the pinned Git objects.
The default checker never invokes these network-capable operations.

## Reproducing the archive

The archive was produced from the exact Git revision and path selection in the
manifest. This recipe writes a candidate into `/tmp`, without changing either
checkout. Set `origin_repo` to a repository containing that revision:

```python
import gzip
from pathlib import Path
import subprocess
import tomllib

origin_repo = Path('/path/to/PQClean')
manifest = tomllib.loads(Path('src/pq/VERSIONS.toml').read_text(encoding='utf8'))
snapshot = manifest['snapshots'][0]
data = subprocess.check_output([
    'git', '-C', str(origin_repo), 'archive', '--format=tar',
    snapshot['upstream_commit'], '--', *snapshot['paths'],
])
with Path('/tmp/pqclean-origin.tar.gz').open('wb') as output:
    with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as archive:
        archive.write(data)
```

The gzip filename and timestamp are omitted. Archive bytes can depend on the
Git/zlib version; origin verification compares the complete selected file names
and contents independently of the archive encoding. The manifest digest pins
the particular stored archive bytes. A deliberate replacement must be reviewed
and reverified against the original Git objects before updating that digest.
Changing the origin revision is a separate maintenance decision, never a side
effect of patch regeneration.
