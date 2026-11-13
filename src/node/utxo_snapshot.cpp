// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/utxo_snapshot.h>

#include <logging.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <txdb.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/readwritefile.h>
#include <validation.h>

#include <cassert>
#include <optional>
#include <string>

namespace node {

bool WriteSnapshotBaseBlockhash(Chainstate& snapshot_chainstate)
{
    AssertLockHeld(::cs_main);
    assert(snapshot_chainstate.m_from_snapshot_blockhash);

    const std::optional<fs::path> chaindir = snapshot_chainstate.CoinsDB().StoragePath();
    assert(chaindir); // Sanity check that chainstate isn't in-memory.
    const fs::path write_to = *chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;

    const auto& hash = *snapshot_chainstate.m_from_snapshot_blockhash;
    if (!WriteBinaryFileAtomic(write_to, std::string{hash.begin(), hash.end()})) {
        LogPrintf("[snapshot] failed to save base blockhash file %s\n",
                  fs::PathToString(write_to));
        return false;
    }
    return true;
}

std::optional<uint256> ReadSnapshotBaseBlockhash(fs::path chaindir)
{
    if (!fs::exists(chaindir)) {
        LogPrintf("[snapshot] cannot read base blockhash: no chainstate dir "
            "exists at path %s\n", fs::PathToString(chaindir));
        return std::nullopt;
    }
    const fs::path read_from = chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;
    const std::string read_from_str = fs::PathToString(read_from);

    const auto contents = ReadBinaryFileBounded(read_from, uint256::size());
    if (contents.status == FileReadStatus::NOT_FOUND) {
        LogPrintf("[snapshot] snapshot chainstate dir is malformed! no base blockhash file "
            "exists at path %s. Try deleting %s and calling loadtxoutset again?\n",
            read_from_str, fs::PathToString(chaindir));
        return std::nullopt;
    }
    if (contents.status != FileReadStatus::OK || contents.data.size() != uint256::size()) {
        throw SnapshotMetadataError{strprintf(
            "Invalid or unreadable snapshot base blockhash file %s: expected exactly %u bytes. "
            "Check file access; if damaged, remove only the snapshot chainstate directory %s "
            "while the node is stopped, then restart and load the snapshot again.",
            read_from_str, uint256::size(), fs::PathToString(chaindir))};
    }
    uint256 base_blockhash;
    SpanReader afile{MakeByteSpan(contents.data)};
    afile >> base_blockhash;
    return base_blockhash;
}

std::optional<fs::path> FindSnapshotChainstateDir(const fs::path& data_dir)
{
    fs::path possible_dir =
        data_dir / fs::u8path(strprintf("chainstate%s", SNAPSHOT_CHAINSTATE_SUFFIX));

    if (fs::exists(possible_dir)) {
        return possible_dir;
    }
    return std::nullopt;
}

} // namespace node
