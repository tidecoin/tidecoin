// Copyright (c) 2018-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EXTERNAL_SIGNER_H
#define BITCOIN_EXTERNAL_SIGNER_H

#include <common/system.h>
#include <univalue.h>

#include <string>
#include <vector>

struct PartiallySignedTransaction;

//! Enables interaction with an external signing device or service, such as
//! a hardware wallet. See doc/external-signer.md
class ExternalSigner
{
private:
    //! The command which handles interaction with the external signer.
    std::vector<std::string> m_command;

    //! Tidecoin network name
    std::string m_chain;

    std::vector<std::string> NetworkArg() const;

public:
    //! @param[in] command      the command which handles interaction with the external signer
    //! @param[in] fingerprint  opaque device selector reported by the bridge
    //! @param[in] chain        "main", "test", or "regtest"
    //! @param[in] name         device name
    ExternalSigner(std::vector<std::string> command, const std::string chain, const std::string& fingerprint, const std::string name);

    //! Opaque device selector reported by the bridge
    std::string m_fingerprint;

    //! Name of signer
    std::string m_name;

    //! Obtain a list of signers. Calls `<command> enumerate`.
    //! @param[in]              command the command which handles interaction with the external signer
    //! @param[in,out] signers  vector to which new signers (with a unique device selector) are added
    //! @param chain            "main", "test", or "regtest"
    //! @returns success
    static bool Enumerate(const std::string& command, std::vector<ExternalSigner>& signers, const std::string chain);

    //! Display address on the device. Calls `<command> displayaddress --desc <descriptor>`.
    //! @param[in] descriptor Descriptor specifying which address to display.
    //!            Must contain fixed public keys; seed identifiers do not enable public derivation.
    UniValue DisplayAddress(const std::string& descriptor) const;

    //! Get receive and change Descriptor(s) from device for a given account.
    //! Calls `<command> getdescriptors --account <account>`
    //! @param[in] account  signer account (wallet enrollment currently uses account 0)
    //! @returns see doc/external-signer.md
    UniValue GetDescriptors(const int account) const;

    //! Sign PartiallySignedTransaction on the device.
    //! Calls `<command> signtx` and passes the PSBT via stdin.
    //! @param[in,out] psbt  PartiallySignedTransaction to be signed
    bool SignTransaction(PartiallySignedTransaction& psbt, std::string& error, unsigned int script_verify_flags);

    //! Merge only signatures on the requested transaction. Rejection leaves psbt unchanged.
    static bool MergeSignatures(PartiallySignedTransaction& psbt, const PartiallySignedTransaction& response,
                               std::string& error, unsigned int script_verify_flags);
};

#endif // BITCOIN_EXTERNAL_SIGNER_H
