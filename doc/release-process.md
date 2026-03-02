Release Process
====================

## Branch updates

### Before every release candidate

* Update release candidate version in `CMakeLists.txt` (`CLIENT_VERSION_RC`).
* Update manpages (after rebuilding the binaries), see [gen-manpages.py](/contrib/devtools/README.md#gen-manpagespy).
* Update tidecoin.conf and commit changes if they exist, see [gen-tidecoin-conf.sh](/contrib/devtools/README.md#gen-tidecoin-confsh).

### Before every major and minor release

* Update version in `CMakeLists.txt` (don't forget to set `CLIENT_VERSION_RC` to `0`).
* Update manpages (see previous section)
* Write release notes (see "Write the release notes" below) in
  `doc/release-notes.md`.

### Before every major release

* On both the master branch and the new release branch:
  - update `CLIENT_VERSION_MAJOR` in [`CMakeLists.txt`](../CMakeLists.txt)
* On the new release branch in [`CMakeLists.txt`](../CMakeLists.txt):
  - set `CLIENT_VERSION_MINOR` to `0`
  - set `CLIENT_VERSION_BUILD` to `0`
  - set `CLIENT_VERSION_IS_RELEASE` to `true`

#### Before branch-off

* Update translations see [translation_process.md](/doc/translation_process.md#synchronising-translations).
* Update hardcoded [seeds](/contrib/seeds/README.md).
* Update the following variables in [`src/kernel/chainparams.cpp`](/src/kernel/chainparams.cpp) for mainnet and testnet:
  - `m_assumed_blockchain_size` and `m_assumed_chain_state_size` with the current size plus some overhead (see
    [this](#how-to-calculate-assumed-blockchain-and-chain-state-size) for information on how to calculate them).
  - The following updates should be reviewed with `reindex-chainstate` and `assumevalid=0` to catch any defect
    that causes rejection of blocks in the past history.
  - `chainTxData` with statistics about the transaction count and rate. Use the output of the `getchaintxstats` RPC with an
    `nBlocks` of 4096 (28 days) and a `bestblockhash` of RPC `getbestblockhash`. Reviewers can verify the results by running
    `getchaintxstats <window_block_count> <window_final_block_hash>` with the `window_block_count` and `window_final_block_hash` from your output.
  - `defaultAssumeValid` with the output of RPC `getblockhash` using the `height` of `window_final_block_height` above
    (and update the block height comment with that height), taking into account the following:
    - On mainnet, the selected value must not be orphaned, so it may be useful to set the height two blocks back from the tip.
    - Testnet should be set with a height some tens of thousands back from the tip, due to reorgs there.
  - `nMinimumChainWork` with the "chainwork" value of RPC `getblockheader` using the same height as that selected for the previous step.
  - `m_assumeutxo_data` array should be appended to with the values returned by calling `tidecoin-cli -rpcclienttimeout=0 -named dumptxoutset utxo.dat rollback=<height or hash>`
    The same height considerations for `defaultAssumeValid` apply.
* Consider updating the headers synchronization tuning parameters to account for the chainparams updates.
  The optimal values change very slowly, so this isn't strictly necessary every release, but doing so doesn't hurt.
  - Update configuration variables in [`contrib/devtools/headerssync-params.py`](/contrib/devtools/headerssync-params.py):
    - Set `TIME` to the software's expected supported lifetime -- after this time, its ability to defend against a high bandwidth timewarp attacker will begin to degrade.
    - Set `MINCHAINWORK_HEADERS` to the height used for the `nMinimumChainWork` calculation above.
    - Check that the other variables still look reasonable.
  - Run the script. It works fine in CPython, but PyPy is much faster (seconds instead of minutes): `pypy3 contrib/devtools/headerssync-params.py`.
  - Paste the output defining `HEADER_COMMITMENT_PERIOD` and `REDOWNLOAD_BUFFER_SIZE` into the top of [`src/headerssync.cpp`](/src/headerssync.cpp).
- Translations on Transifex:
    - Pull latest translations and commit them on the branch.
    - Tidecoin currently uses a stable resource configured in [`.tx/config`](/.tx/config):
      `o:tidecoin:p:tidecoin:r:qt-translation`.
    - Do not rotate the resource slug per release unless there is a deliberate Transifex migration.
    - Ensure the source file in Transifex matches `src/qt/locale/bitcoin_en.xlf`.

#### After branch-off (on the major release branch)

- Update the versions.
- Keep `doc/release-notes.md` as the canonical draft on the release branch.
- Create a pinned meta-issue for testing the release candidate in
  `tidecoin/tidecoin`, and include links to candidate binaries and
  `doc/release-notes.md`.
- Translations on Transifex
    - If you run branch-specific translation sync, point the Transifex source URL to the release branch:
      `https://raw.githubusercontent.com/tidecoin/tidecoin/<branch>/src/qt/locale/bitcoin_en.xlf`.

#### Before final release

- Finalize `doc/release-notes.md` on the release branch.
- Ensure the release-candidate meta-issue has no unresolved release blockers.
- Ensure release-note labeling/tracking is complete for all included PRs/issues.

#### Tagging a release (candidate)

Tag directly with git from the repository root:

```sh
VERSION='1.0.1' # example
git fetch origin --tags
git tag -s "v${VERSION}" -m "Tidecoin ${VERSION}"
git push origin "v${VERSION}"
```

Before tagging, verify `CMakeLists.txt`, `doc/release-notes.md`, manpages, and
`share/examples/tidecoin.conf` are in their final state.

## Building

### First time / New builders

Install Guix using one of the installation methods detailed in
[contrib/guix/INSTALL.md](/contrib/guix/INSTALL.md).

Check out the source code in the following directory hierarchy.

    cd /path/to/your/toplevel/build
    git clone <url-to-your-guix-sigs-repo> ./guix.sigs
    git clone <url-to-your-detached-sigs-repo> ./tidecoin-detached-sigs
    git clone <url-to-your-tidecoin-repo> ./tidecoin

### Write the release notes

Keep `doc/release-notes.md` in the release branch as the single source of
truth while drafting and reviewing notes. For collaboration, use pull requests
and/or an issue thread in `tidecoin/tidecoin`.

Generate list of authors:

    git log --format='- %aN' v(current version, e.g. 0.18.3)..v(new version, e.g. 1.0.0) | grep -v 'merge-script' | sort -fiu

### Setup and perform Guix builds

Checkout the Tidecoin version you'd like to build:

```sh
pushd ./tidecoin
SIGNER='(your builder key)'
VERSION='(new version without v-prefix, e.g. 1.0.0)'
git fetch origin "v${VERSION}"
git checkout "v${VERSION}"
popd
```

Ensure your guix.sigs are up-to-date if you wish to `guix-verify` your builds
against other `guix-attest` signatures.

```sh
git -C ./guix.sigs pull
```

### Create the macOS SDK tarball (first time, or when SDK version changes)

Create the macOS SDK tarball, see the [macdeploy
instructions](/contrib/macdeploy/README.md#sdk-extraction) for
details.

### Build and attest to build outputs

Follow the relevant Guix README.md sections:
- [Building](/contrib/guix/README.md#building)
- [Attesting to build outputs](/contrib/guix/README.md#attesting-to-build-outputs)

### Verify other builders' signatures to your own (optional)

- [Verifying build output attestations](/contrib/guix/README.md#verifying-build-output-attestations)

### Commit your non codesigned signature to guix.sigs

```sh
pushd ./guix.sigs
git add "${VERSION}/${SIGNER}"/noncodesigned.SHA256SUMS{,.asc}
git commit -m "Add attestations by ${SIGNER} for ${VERSION} non-codesigned"
popd
```

Then open a Pull Request to your `guix.sigs` repository.

## Codesigning

### macOS codesigner only: Create detached macOS signatures (assuming [signapple](https://github.com/achow101/signapple/) is installed and up to date with master branch)

In the `guix-build-${VERSION}/output/x86_64-apple-darwin` and `guix-build-${VERSION}/output/arm64-apple-darwin` directories:

    tar xf tidecoin-${VERSION}-${ARCH}-apple-darwin-codesigning.tar.gz
    ./detached-sig-create.sh /path/to/codesign.p12 /path/to/AuthKey_foo.p8 uuid
    Enter the keychain password and authorize the signature
    signature-osx-${ARCH}.tar.gz will be created

### Windows codesigner only: Create detached Windows signatures

In the `guix-build-${VERSION}/output/x86_64-w64-mingw32` directory:

    tar xf tidecoin-${VERSION}-win64-codesigning.tar.gz
    ./detached-sig-create.sh /path/to/codesign.key
    Enter the passphrase for the key when prompted
    signature-win.tar.gz will be created

### Windows and macOS codesigners only: test code signatures
It is advised to test that the code signature attaches properly prior to tagging by performing the `guix-codesign` step.
However if this is done, once the release has been tagged in the detached-signatures repo, the `guix-codesign` step must be performed again in order for the guix attestation to be valid when compared against the attestations of non-codesigner builds. The directories created by `guix-codesign` will need to be cleared prior to running `guix-codesign` again.

### Windows and macOS codesigners only: Commit the detached codesign payloads

```sh
pushd ./tidecoin-detached-sigs
# checkout or create the appropriate branch for this release series
git checkout --orphan <branch>
# if you are the macOS codesigner
rm -rf osx
tar xf signature-osx-x86_64.tar.gz
tar xf signature-osx-arm64.tar.gz
# if you are the windows codesigner
rm -rf win
tar xf signature-win.tar.gz
git add -A
git commit -m "<version>: {osx,win} signature for {rc,final}"
git tag -s "v${VERSION}" HEAD
git push the current branch and new tag
popd
```

### Non-codesigners: wait for Windows and macOS detached signatures

- Once the Windows and macOS builds each have at least 2 matching signatures,
  they can be signed with their respective release keys. For major releases,
  3+ matching signatures are recommended.
- Detached signatures are then committed to your detached-signatures repository, which can be combined with the unsigned apps to create signed binaries.

### Create the codesigned build outputs

- [Codesigning build outputs](/contrib/guix/README.md#codesigning-build-outputs)

### Verify other builders' signatures to your own (optional)

- [Verifying build output attestations](/contrib/guix/README.md#verifying-build-output-attestations)

### Commit your codesigned signature to guix.sigs (for the signed macOS/Windows binaries)

```sh
pushd ./guix.sigs
git add "${VERSION}/${SIGNER}"/all.SHA256SUMS{,.asc}
git commit -m "Add attestations by ${SIGNER} for ${VERSION} codesigned"
popd
```

Then open a Pull Request to your `guix.sigs` repository.

## After at least 2 independent Guix builds match (small-team baseline)

After verifying signatures, combine the `all.SHA256SUMS.asc` file from all
signers into `SHA256SUMS.asc`:

```bash
cat "$VERSION"/*/all.SHA256SUMS.asc > SHA256SUMS.asc
```


- Upload to your release hosting server:
    1. The contents of each `./tidecoin/guix-build-${VERSION}/output/${HOST}/` directory.

       Guix will output all of the results into host subdirectories, but the SHA256SUMS
       file does not include these subdirectories. In order for downloads via torrent
       to verify without directory structure modification, all of the uploaded files
       need to be in the same directory as the SHA256SUMS file.

       Wait until all of these files have finished uploading before uploading the SHA256SUMS(.asc) files.

    2. The `SHA256SUMS` file

    3. The `SHA256SUMS.asc` combined signature file you just created.

- After uploading release candidate binaries, notify your project's developer/community channels
  that a release candidate is available for testing. Include a link to the release
  notes draft.

- The server will automatically create an OpenTimestamps file and torrent of the directory.

- Optionally help seed this torrent. To get the `magnet:` URI use:

  ```sh
  transmission-show -m <torrent file>
  ```

  Insert the magnet URI into the announcement sent to mailing lists. This permits
  people without access to your primary release host to download the binary distribution.
  Also publish it in your release metadata.

- Keep final notes in `doc/release-notes.md` on the release branch and link to
  them from the GitHub release page. If your branch maintains a
  `doc/release-notes/` archive directory, you may also copy notes there.

- Update your project website/release portal

  - blog post

  - maintained versions table

  - RPC documentation update

      - Regenerate and publish RPC documentation


- Update repositories

  - Delete post-EOL release branches and create a tag `v${branch_name}-final`.

  - Delete "Needs backport" labels for non-existing branches.

  - Update packaging repos

      - Push/update Flatpak packaging

      - Push/update Snap packaging

  - Create a new GitHub release with a link to `doc/release-notes.md` in the
    tagged release branch

- Announce the release using your project's official channels.

### Additional information

#### <a name="how-to-calculate-assumed-blockchain-and-chain-state-size"></a>How to calculate `m_assumed_blockchain_size` and `m_assumed_chain_state_size`

Both variables are used as a guideline for how much space the user needs on their drive in total, not just strictly for the blockchain.
Note that all values should be taken from a **fully synced** node and have an overhead of 5-10% added on top of its base value.

To calculate `m_assumed_blockchain_size`, take the size in GiB of these directories:
- For `mainnet` -> the data directory, excluding the `/testnet` and `/regtest` directories and any overly large files, e.g. a huge `debug.log`
- For `testnet` -> `/testnet`

To calculate `m_assumed_chain_state_size`, take the size in GiB of these directories:
- For `mainnet` -> `/chainstate`
- For `testnet` -> `/testnet/chainstate`

Notes:
- When taking the size for `m_assumed_blockchain_size`, there's no need to exclude the `/chainstate` directory since it's a guideline value and an overhead will be added anyway.
- The expected overhead for growth may change over time. Consider whether the percentage needs to be changed in response; if so, update it here in this section.
