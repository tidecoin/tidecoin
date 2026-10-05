// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_TEST_UTIL_H
#define BITCOIN_WALLET_TEST_UTIL_H

#include <addresstype.h>
#include <wallet/db.h>
#include <wallet/scriptpubkeyman.h>

#include <memory>
#include <optional>

class ArgsManager;
class CChain;
class CKey;
enum class OutputType;
namespace interfaces {
class Chain;
} // namespace interfaces

namespace wallet {
class CWallet;
class WalletDatabase;
struct WalletContext;

static const DatabaseFormat DATABASE_FORMATS[] = {
       DatabaseFormat::SQLITE,
};

const std::string ADDRESS_BCRT1_UNSPENDABLE = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3xueyj";

std::unique_ptr<CWallet> CreateSyncedWallet(interfaces::Chain& chain, CChain& cchain, const CKey& key);

std::shared_ptr<CWallet> TestLoadWallet(WalletContext& context);
std::shared_ptr<CWallet> TestLoadWallet(std::unique_ptr<WalletDatabase> database, WalletContext& context, uint64_t create_flags);
void TestUnloadWallet(std::shared_ptr<CWallet>&& wallet);

// Creates a copy of the provided database
std::unique_ptr<WalletDatabase> DuplicateMockDatabase(WalletDatabase& database);

/** Returns a new encoded destination from the wallet (hardcoded to BECH32) */
std::string getnewaddress(CWallet& w);
/** Returns a new destination, of an specific type, from the wallet */
CTxDestination getNewDestination(CWallet& w, OutputType output_type);

using MockableData = std::map<SerializeData, SerializeData, std::less<>>;

class MockableCursor: public DatabaseCursor
{
public:
    MockableData::const_iterator m_cursor;
    MockableData::const_iterator m_cursor_end;
    bool m_pass;

    explicit MockableCursor(const MockableData& records, bool pass) : m_cursor(records.begin()), m_cursor_end(records.end()), m_pass(pass) {}
    MockableCursor(const MockableData& records, bool pass, std::span<const std::byte> prefix);
    ~MockableCursor() = default;

    Status Next(DataStream& key, DataStream& value) override;
};

class MockableBatch : public DatabaseBatch
{
private:
    MockableData& m_records;
    bool m_pass;
    std::optional<MockableData> m_before_txn;

    bool ReadKey(DataStream&& key, DataStream& value) override;
    bool WriteKey(DataStream&& key, DataStream&& value, bool overwrite=true) override;
    bool EraseKey(DataStream&& key) override;
    bool HasKey(DataStream&& key) override;
    bool ErasePrefix(std::span<const std::byte> prefix) override;

public:
    explicit MockableBatch(MockableData& records, bool pass) : m_records(records), m_pass(pass) {}
    ~MockableBatch() { if (m_before_txn) m_records = std::move(*m_before_txn); }

    void Close() override {}

    std::unique_ptr<DatabaseCursor> GetNewCursor() override
    {
        return std::make_unique<MockableCursor>(m_records, m_pass);
    }
    std::unique_ptr<DatabaseCursor> GetNewPrefixCursor(std::span<const std::byte> prefix) override {
        return std::make_unique<MockableCursor>(m_records, m_pass, prefix);
    }
    bool TxnBegin() override {
        if (!m_pass || m_before_txn) return false;
        m_before_txn = m_records;
        return true;
    }
    bool TxnCommit() override {
        if (!m_pass || !m_before_txn) return false;
        m_before_txn.reset();
        return true;
    }
    bool TxnAbort() override {
        if (!m_pass || !m_before_txn) return false;
        m_records = std::move(*m_before_txn);
        m_before_txn.reset();
        return true;
    }
    bool HasActiveTxn() override { return m_before_txn.has_value(); }
};

/** A WalletDatabase whose contents and return values can be modified as needed for testing
 **/
class MockableDatabase : public WalletDatabase
{
public:
    MockableData m_records;
    bool m_pass{true};

    MockableDatabase(MockableData records = {}) : WalletDatabase(), m_records(records) {}
    ~MockableDatabase() = default;

    void Open() override {}

    bool Rewrite() override { return m_pass; }
    bool Backup(const std::string& strDest) const override { return m_pass; }
    void Close() override {}

    std::string Filename() override { return "mockable"; }
    std::vector<fs::path> Files() override { return {}; }
    std::string Format() override { return "mock"; }
    std::unique_ptr<DatabaseBatch> MakeBatch() override { return std::make_unique<MockableBatch>(m_records, m_pass); }
};

std::unique_ptr<WalletDatabase> CreateMockableWalletDatabase(MockableData records = {});
MockableDatabase& GetMockableDatabase(CWallet& wallet);

DescriptorScriptPubKeyMan* CreateDescriptor(CWallet& keystore, const std::string& desc_str, const bool success);
} // namespace wallet

#endif // BITCOIN_WALLET_TEST_UTIL_H
