// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>

#include <coins.h>
#include <dbwrapper.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <uint256.h>
#include <util/threadnames.h>
#include <util/vector.h>

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <future>
#include <iterator>
#include <utility>

static constexpr uint8_t DB_COIN{'C'};
static constexpr uint8_t DB_BEST_BLOCK{'B'};
static constexpr uint8_t DB_HEAD_BLOCKS{'H'};
static constexpr uint8_t DB_CHAINSTATE_FORMAT{'F'};
// Keys used in previous version that might still be found in the DB:
static constexpr uint8_t DB_COINS{'c'};
static constexpr uint8_t CHAINSTATE_FORMAT_CURRENT{1};

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    uint8_t key{DB_COIN};
    explicit CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)) {}

    SERIALIZE_METHODS(CoinEntry, obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }
};

bool IsCurrentCoinSerialization(const std::string& value)
{
    try {
        DataStream stream{MakeByteSpan(value)};
        Coin coin;
        stream >> coin;
        return stream.empty();
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace

bool CCoinsViewDB::NeedsUpgrade()
{
    return GetFormatState() == CoinsDBFormatState::NEEDS_UPGRADE;
}

CoinsDBFormatState CCoinsViewDB::GetFormatState()
{
    std::unique_ptr<CDBIterator> cursor{m_db->NewIterator()};

    // DB_COINS was deprecated in v0.15.0, commit
    // 1088b02f0ccd7358d2b7076bb9e122d59d502d02
    cursor->Seek(std::make_pair(DB_COINS, uint256{}));
    if (cursor->Valid()) return CoinsDBFormatState::NEEDS_UPGRADE;

    uint8_t format_version{0};
    if (m_db->Read(DB_CHAINSTATE_FORMAT, format_version)) {
        return format_version == CHAINSTATE_FORMAT_CURRENT
            ? CoinsDBFormatState::OK
            : CoinsDBFormatState::LEGACY_SCRIPT_COMPRESSION;
    }

    cursor->Seek(DB_COIN);
    while (cursor->Valid()) {
        COutPoint outpoint;
        CoinEntry entry{&outpoint};
        if (!cursor->GetKey(entry) || entry.key != DB_COIN) break;

        std::string raw_value;
        if (!cursor->GetValueRaw(raw_value) || !IsCurrentCoinSerialization(raw_value)) {
            return CoinsDBFormatState::LEGACY_SCRIPT_COMPRESSION;
        }
        cursor->Next();
    }

    if (!m_db->Write(DB_CHAINSTATE_FORMAT, CHAINSTATE_FORMAT_CURRENT)) {
        throw dbwrapper_error{"Failed to persist chainstate format marker"};
    }
    return CoinsDBFormatState::OK;
}

CCoinsViewDB::CCoinsViewDB(DBParams db_params, CoinsViewOptions options) :
    m_db_params{std::move(db_params)},
    m_options{std::move(options)},
    m_db{std::make_unique<CDBWrapper>(m_db_params)} { }

CCoinsViewDB::~CCoinsViewDB()
{
    if (m_compaction.valid()) {
        if (m_compaction.wait_for(std::chrono::seconds{0}) != std::future_status::ready) {
            LogInfo("Waiting for background chainstate compaction of %s", fs::PathToString(m_db_params.path));
        }
        m_compaction.wait();
    }
}

void CCoinsViewDB::ResizeCache(size_t new_cache_size)
{
    // We can't do this operation with an in-memory DB since we'll lose all the coins upon
    // reset.
    if (!m_db_params.memory_only) {
        LOCK(m_db_mutex);
        const std::lock_guard cursor_lock{m_cursor_mutex};
        // Have to do a reset first to get the original `m_db` state to release its
        // filesystem lock.
        m_db.reset();
        m_db_params.cache_bytes = new_cache_size;
        m_db_params.wipe_data = false;
        m_db = std::make_unique<CDBWrapper>(m_db_params);
    }
}

std::shared_future<void> CCoinsViewDB::CompactFullAsync()
{
    AssertLockHeld(::cs_main);
    if (m_compaction.valid() && m_compaction.wait_for(std::chrono::seconds{0}) != std::future_status::ready) return m_compaction;
    m_compaction = std::async(std::launch::async, [this] {
        try {
            util::ThreadRename("utxocompact");
            LOCK(m_db_mutex);
            LogDebug(BCLog::COINDB, "Starting chainstate compaction of %s", fs::PathToString(m_db_params.path));
            m_db->CompactFull();
            LogDebug(BCLog::COINDB, "Finished chainstate compaction of %s", fs::PathToString(m_db_params.path));
        } catch (const std::exception& e) {
            LogWarning("Failed chainstate compaction (%s)", e.what());
        }
    }).share();
    return m_compaction;
}

std::optional<std::string> CCoinsViewDB::GetDBProperty(const std::string& property) const
{
    return m_db->GetProperty(property);
}

std::optional<Coin> CCoinsViewDB::GetCoin(const COutPoint& outpoint) const
{
    if (Coin coin; m_db->Read(CoinEntry(&outpoint), coin)) return coin;
    return std::nullopt;
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const {
    return m_db->Exists(CoinEntry(&outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!m_db->Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const {
    std::vector<uint256> vhashHeadBlocks;
    if (!m_db->Read(DB_HEAD_BLOCKS, vhashHeadBlocks)) {
        return std::vector<uint256>();
    }
    return vhashHeadBlocks;
}

bool CCoinsViewDB::BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) {
    CDBBatch batch(*m_db);
    size_t count = 0;
    size_t changed = 0;
    assert(!hashBlock.IsNull());

    const bool has_changes{cursor.Begin() != cursor.End()};
    size_t batches_written{0};
    const auto crash = [] {
        LogPrintf("Simulating deterministic chainstate crash.\n");
        _Exit(1);
    };
    if (has_changes && m_options.simulate_crash_after_batch == 0) crash();

    uint256 old_tip = GetBestBlock();
    if (old_tip.IsNull()) {
        // We may be in the middle of replaying.
        std::vector<uint256> old_heads = GetHeadBlocks();
        if (old_heads.size() == 2) {
            if (old_heads[0] != hashBlock) {
                LogPrintLevel(BCLog::COINDB, BCLog::Level::Error, "The coins database detected an inconsistent state, likely due to a previous crash or shutdown. You will need to restart tidecoind with the -reindex-chainstate or -reindex configuration option.\n");
            }
            assert(old_heads[0] == hashBlock);
            old_tip = old_heads[1];
        }
    }

    // In the first batch, mark the database as being in the middle of a
    // transition from old_tip to hashBlock.
    // A vector is used for future extensibility, as we may want to support
    // interrupting after partial writes from multiple independent reorgs.
    batch.Erase(DB_BEST_BLOCK);
    batch.Write(DB_HEAD_BLOCKS, Vector(hashBlock, old_tip));

    for (auto it{cursor.Begin()}; it != cursor.End();) {
        if (it->second.IsDirty()) {
            CoinEntry entry(&it->first);
            if (it->second.coin.IsSpent()) {
                batch.Erase(entry);
            } else {
                batch.Write(entry, it->second.coin);
            }

            changed++;
        }
        count++;
        it = cursor.NextAndMaybeErase(*it);
        if (batch.ApproximateSize() > m_options.batch_write_bytes) {
            LogDebug(BCLog::COINDB, "Writing partial batch of %.2f MiB\n", batch.ApproximateSize() * (1.0 / 1048576.0));

            m_db->WriteBatch(batch);
            batch.Clear();
            ++batches_written;
            if (has_changes && m_options.simulate_crash_after_batch == batches_written) crash();
            if (m_options.simulate_crash_ratio) {
                static FastRandomContext rng;
                if (rng.randrange(m_options.simulate_crash_ratio) == 0) {
                    LogPrintf("Simulating a crash. Goodbye.\n");
                    _Exit(0);
                }
            }
        }
    }

    // In the last batch, mark the database as consistent with hashBlock again.
    if (has_changes && m_options.simulate_crash_before_final) crash();
    batch.Erase(DB_HEAD_BLOCKS);
    batch.Write(DB_BEST_BLOCK, hashBlock);
    batch.Write(DB_CHAINSTATE_FORMAT, CHAINSTATE_FORMAT_CURRENT);

    LogDebug(BCLog::COINDB, "Writing final batch of %.2f MiB\n", batch.ApproximateSize() * (1.0 / 1048576.0));
    bool ret = m_db->WriteBatch(batch);
    LogDebug(BCLog::COINDB, "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return ret;
}

size_t CCoinsViewDB::EstimateSize() const
{
    return m_db->EstimateSize(DB_COIN, uint8_t(DB_COIN + 1));
}

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor: public CCoinsViewCursor
{
public:
    // Prefer using CCoinsViewDB::Cursor() since we want to perform some
    // cache warmup on instantiation.
    CCoinsViewDBCursor(CDBIterator* pcursorIn, const uint256&hashBlockIn):
        CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn) {}
    ~CCoinsViewDBCursor() = default;

    bool GetKey(COutPoint &key) const override;
    bool GetValue(Coin &coin) const override;

    bool Valid() const override;
    void Next() override;

private:
    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, COutPoint> keyTmp;

    friend class CCoinsViewDB;
};

std::unique_ptr<CCoinsViewCursor> CCoinsViewDB::Cursor() const
{
    auto i = std::make_unique<CCoinsViewDBCursor>(
        const_cast<CDBWrapper&>(*m_db).NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COIN);
    // Cache key of first record
    if (i->pcursor->Valid()) {
        CoinEntry entry(&i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key;
    } else {
        i->keyTmp.first = 0; // Make sure Valid() and GetKey() return false
    }
    return i;
}

namespace {
class CacheLockedCoinsCursor final : public CCoinsViewCursor
{
    // Destroy the iterator before releasing the cache-reopen lock.
    std::unique_lock<std::mutex> m_lock;
    std::unique_ptr<CCoinsViewCursor> m_cursor;
public:
    CacheLockedCoinsCursor(std::unique_lock<std::mutex> lock, std::unique_ptr<CCoinsViewCursor> cursor)
        : CCoinsViewCursor(cursor->GetBestBlock()), m_lock(std::move(lock)), m_cursor(std::move(cursor)) {}
    bool GetKey(COutPoint& key) const override { return m_cursor->GetKey(key); }
    bool GetValue(Coin& coin) const override { return m_cursor->GetValue(coin); }
    bool Valid() const override { return m_cursor->Valid(); }
    void Next() override { m_cursor->Next(); }
};
}

std::unique_ptr<CCoinsViewCursor> CCoinsViewDB::CursorWithCacheLock() const
{
    AssertLockHeld(cs_main);
    std::unique_lock lock{m_cursor_mutex};
    auto cursor{Cursor()};
    return std::make_unique<CacheLockedCoinsCursor>(std::move(lock), std::move(cursor));
}

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    return pcursor->GetValue(coin);
}

bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COIN;
}

void CCoinsViewDBCursor::Next()
{
    pcursor->Next();
    CoinEntry entry(&keyTmp.second);
    if (!pcursor->Valid() || !pcursor->GetKey(entry)) {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    } else {
        keyTmp.first = entry.key;
    }
}
