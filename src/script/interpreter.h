// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include <consensus/amount.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script_error.h> // IWYU pragma: export
#include <span.h>
#include <uint256.h>
#include <uint512.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

class CPubKey;
class CScript;
class CScriptNum;
struct CScriptWitness;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

/** Script verification flags.
 *
 *  All flags are intended to be soft forks: the set of acceptable scripts under
 *  flags (A | B) is a subset of the acceptable scripts under flag (A).
 */
enum : uint32_t {
    SCRIPT_VERIFY_NONE      = 0,

    // Evaluate P2SH subscripts (BIP16).
    SCRIPT_VERIFY_P2SH      = (1U << 0),

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = (1U << 1),

    // Using a non-push operator in the scriptSig causes script failure (BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 2),

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    SCRIPT_VERIFY_MINIMALDATA = (1U << 3),

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    // NOPs that have associated forks to give them new meaning (CLTV, CSV)
    // are not subject to this rule.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS  = (1U << 4),

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH or WITNESS.
    // Note: WITNESS_V0 script execution has behavior similar to CLEANSTACK as part of its
    //       consensus rules. It is automatic there and does not need this flag.
    SCRIPT_VERIFY_CLEANSTACK = (1U << 5),

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 6),

    // support CHECKSEQUENCEVERIFY opcode
    //
    // See BIP112 for details
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 7),

    // Support segregated witness
    //
    SCRIPT_VERIFY_WITNESS = (1U << 8),

    // Reject non-v0 witness programs (segwit v1+ disabled).
    //
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1U << 9),

    // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    // Note: WITNESS_V0 script execution has behavior similar to MINIMALIF as part of its policy
    //       rules. It is automatic there and does not depend on this flag.
    SCRIPT_VERIFY_MINIMALIF = (1U << 10),

    // Signature(s) must be empty vector if a CHECK(MULTI)SIG operation failed
    //
    SCRIPT_VERIFY_NULLFAIL = (1U << 11),

    // Making OP_CODESEPARATOR and FindAndDelete fail any non-segwit scripts
    //
    SCRIPT_VERIFY_CONST_SCRIPTCODE = (1U << 12),

    // Activate additional PQ schemes and reject legacy Falcon-512 signatures.
    // Without this flag, only Falcon-512 may authorize signature checks.
    SCRIPT_VERIFY_PQ_STRICT = (1U << 13),

    // Enable witness v1 64-byte scripthash validation (post-auxpow).
    SCRIPT_VERIFY_WITNESS_V1_512 = (1U << 14),

    // Enable OP_SHA512 opcode (post-auxpow).
    SCRIPT_VERIFY_SHA512 = (1U << 15),

    // Constants to point to the highest flag in use. Add new flags above this line.
    //
    SCRIPT_VERIFY_END_MARKER
};

struct PrecomputedTransactionData
{
    // Single-SHA256 precomputed data shared by witness v0 sighash.
    uint256 m_prevouts_single_hash;
    uint256 m_sequences_single_hash;
    uint256 m_outputs_single_hash;

    // BIP143 precomputed data (double-SHA256).
    uint256 hashPrevouts, hashSequence, hashOutputs;
    //! Whether the 3 fields above are initialized.
    bool m_bip143_segwit_ready = false;

    // SHA-512 precomputed data for witness v1_512 sighash.
    uint512 hashPrevouts_512, hashSequence_512, hashOutputs_512;
    //! Whether the 3 fields above are initialized.
    bool m_bip143_segwit512_ready = false;

    std::vector<CTxOut> m_spent_outputs;
    //! Whether m_spent_outputs is initialized.
    bool m_spent_outputs_ready = false;

    PrecomputedTransactionData() = default;

    /** Initialize this PrecomputedTransactionData with transaction data.
     *
     * @param[in]   tx             The transaction for which data is being precomputed.
     * @param[in]   spent_outputs  The CTxOuts being spent, one for each tx.vin, in order.
     * @param[in]   force          Whether to precompute data for all optional features,
     *                             regardless of what is in the inputs (used at signing
     *                             time, when the inputs aren't filled in yet). */
    template <class T>
    void Init(const T& tx, std::vector<CTxOut>&& spent_outputs, bool force = false);

    template <class T>
    explicit PrecomputedTransactionData(const T& tx);
};

enum class SigVersion
{
    BASE = 0,        //!< Bare scripts and BIP16 P2SH-wrapped redeemscripts
    WITNESS_V0 = 1,  //!< Witness v0 (P2WPKH and P2WSH); see BIP 141
    WITNESS_V1_512 = 2, //!< Witness v1 (P2WSH-512)
};

struct ScriptExecutionData
{
};

/** Signature hash sizes */
static constexpr size_t WITNESS_V0_SCRIPTHASH_SIZE = 32;
static constexpr size_t WITNESS_V0_KEYHASH_SIZE = 20;
static constexpr size_t WITNESS_V1_SCRIPTHASH_512_SIZE = 64;

/** Data structure to cache SHA256 midstates for the Post Quantum sighash calculations
 *  (bare, P2SH, P2WPKH, P2WSH). */
class SigHashCache
{
    /** For each sighash mode (ALL, SINGLE, NONE, ALL|ANYONE, SINGLE|ANYONE, NONE|ANYONE),
     *  optionally store a scriptCode which the hash is for, plus a midstate for the SHA256
     *  computation just before adding the hash_type itself. */
    std::optional<std::pair<CScript, HashWriter>> m_cache_entries[6];

    /** Given a hash_type, find which of the 6 cache entries is to be used. */
    int CacheIndex(int32_t hash_type) const noexcept;

public:
    /** Load into writer the SHA256 midstate if found in this cache. */
    [[nodiscard]] bool Load(int32_t hash_type, const CScript& script_code, HashWriter& writer) const noexcept;
    /** Store into this cache object the provided SHA256 midstate. */
    void Store(int32_t hash_type, const CScript& script_code, const HashWriter& writer) noexcept;
};

template <class T>
uint256 SignatureHash(const CScript& scriptCode, const T& txTo, unsigned int nIn, int32_t nHashType, const CAmount& amount, SigVersion sigversion, const PrecomputedTransactionData* cache = nullptr, SigHashCache* sighash_cache = nullptr);

template <class T>
uint512 SignatureHash512(const CScript& scriptCode, const T& txTo, unsigned int nIn, int32_t nHashType, const CAmount& amount, const PrecomputedTransactionData* cache = nullptr);

class BaseSignatureChecker
{
public:
    virtual bool CheckPostQuantumSignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
    {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum& nLockTime) const
    {
         return false;
    }

    virtual bool CheckSequence(const CScriptNum& nSequence) const
    {
         return false;
    }

    virtual ~BaseSignatureChecker() = default;
};

/** Enum to specify what *TransactionSignatureChecker's behavior should be
 *  when dealing with missing transaction data.
 */
enum class MissingDataBehavior
{
    ASSERT_FAIL,  //!< Abort execution through assertion failure (for consensus code)
    FAIL,         //!< Just act as if the signature was invalid
};

template <class T>
class GenericTransactionSignatureChecker : public BaseSignatureChecker
{
private:
    const T* txTo;
    const MissingDataBehavior m_mdb;
    unsigned int nIn;
    const CAmount amount;
    const PrecomputedTransactionData* txdata;
    // Preactivation mode: Falcon-512 only, with legacy verification permitted.
    // Chain-connected callers derive this from SCRIPT_VERIFY_PQ_STRICT.
    const bool m_allow_legacy;
    mutable SigHashCache m_sighash_cache;

protected:
    virtual bool VerifyPostQuantumSignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;
    virtual bool VerifyPostQuantumSignature512(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint512& sighash) const;
    bool AllowLegacy() const { return m_allow_legacy; }

public:
    GenericTransactionSignatureChecker(const T* txToIn, unsigned int nInIn, const CAmount& amountIn, MissingDataBehavior mdb, bool allow_legacy = false) : txTo(txToIn), m_mdb(mdb), nIn(nInIn), amount(amountIn), txdata(nullptr), m_allow_legacy(allow_legacy) {}
    GenericTransactionSignatureChecker(const T* txToIn, unsigned int nInIn, const CAmount& amountIn, const PrecomputedTransactionData& txdataIn, MissingDataBehavior mdb, bool allow_legacy = false) : txTo(txToIn), m_mdb(mdb), nIn(nInIn), amount(amountIn), txdata(&txdataIn), m_allow_legacy(allow_legacy) {}
    bool CheckPostQuantumSignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override;
    bool CheckLockTime(const CScriptNum& nLockTime) const override;
    bool CheckSequence(const CScriptNum& nSequence) const override;
};

using TransactionSignatureChecker = GenericTransactionSignatureChecker<CTransaction>;
using MutableTransactionSignatureChecker = GenericTransactionSignatureChecker<CMutableTransaction>;

class DeferringSignatureChecker : public BaseSignatureChecker
{
protected:
    const BaseSignatureChecker& m_checker;

public:
    DeferringSignatureChecker(const BaseSignatureChecker& checker) : m_checker(checker) {}

    bool CheckPostQuantumSignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        return m_checker.CheckPostQuantumSignature(scriptSig, vchPubKey, scriptCode, sigversion);
    }

    bool CheckLockTime(const CScriptNum& nLockTime) const override
    {
        return m_checker.CheckLockTime(nLockTime);
    }
    bool CheckSequence(const CScriptNum& nSequence) const override
    {
        return m_checker.CheckSequence(nSequence);
    }
};

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* error = nullptr);
bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* error = nullptr);
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror = nullptr);

size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags);

int FindAndDelete(CScript& script, const CScript& b);

#endif // BITCOIN_SCRIPT_INTERPRETER_H
