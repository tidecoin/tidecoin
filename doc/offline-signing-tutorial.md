# Offline Signing Tutorial

This tutorial will describe how to use two instances of Tidecoin, one online and one offline, to greatly increase security by not having private keys reside on a networked device.

Maintaining an air-gap between private keys and any network connections drastically reduces the opportunity for those keys to be exfiltrated from the user.

This workflow uses Partially Signed Tidecoin Transactions (PSBTs) to transfer the transaction to and from the offline wallet for signing using the private keys.

> [!NOTE]
> While this tutorial demonstrates the process using the `testnet` network, you should omit the `-testnet` flag in the provided commands when working with `mainnet`.

## Overview
In this tutorial we have two hosts, both running Tidecoin.

* `offline` host which is disconnected from all networks (internet, Tor, wifi, bluetooth etc.) and does not have, or need, a copy of the blockchain.
* `online` host which is a regular online node with a synced blockchain.

We are going to first create an `offline_wallet` on the offline host and have it issue a receive address and a change address. We will then create a `watch_only_wallet` on the online host from the public descriptors of those two addresses. Next we will receive some coins into the wallet. In order to spend these coins we'll create an unsigned PSBT using the `watch_only_wallet`, sign the PSBT using the private keys in the `offline_wallet`, and finally broadcast the signed PSBT using the online host.

Tidecoin wallets derive their keys from a seed using hardened-only post-quantum derivation (PQHD). Unlike BIP32 extended public keys, a PQHD descriptor such as `wpkh(pqhd(<seed id>)/10084h/1h/7h/0h/0h/*h)` cannot derive further public keys without the seed. The watch-only wallet therefore cannot generate addresses on its own: the offline wallet issues every address, and its fixed public descriptor is transferred to the online host. See [PQHD design, section 12.5](design/pqhd.md#125-finite-public-watch-only-provisioning).

### Requirements
- [jq](https://jqlang.github.io/jq/) installation - This tutorial uses jq to process certain fields from JSON RPC responses, but this convenience is optional.

### Choose the destination rules

The offline node's height does not describe the destination chain. Choose
`pre-auxpow` or `post-auxpow` using the online node's next-block rules and the
activation configuration for the release/network you intend to use. In this
release mainnet activation is disabled; testnet activates at height 1,000, so a
validated testnet tip of 999 already selects post rules. Check the destination's
current height with `getblockcount`; a chain rollback can change the next-block
era. Do not change network activation settings to configure offline signing.

Record the choice with your transaction workflow, outside the PSBT. For example,
for testnet whose next block is at or beyond activation, set this on the offline
host and use it for every analysis, signing and finalization call below:

```sh
[offline]$ RULES=post-auxpow
```

Use `RULES=pre-auxpow` for a destination still before activation. RPC omission or
JSON `null` uses the local next-block era; a genesis-only offline host normally
selects pre rules. An explicit post choice there produces a `warnings` notice,
which is expected. The returned `rules` field records what was actually used.
The standalone `tidecoin-tx` utility uses the same names but requires `-rules`
for signing and verification, with no default.

This tutorial provisions Falcon-512 native-v0 receive and change addresses,
which work without an activated local chain. The processing option does not
create a missing native-v1 descriptor or enable `getnewaddress` or
`getrawchangeaddress` before activation. To provision newer receiving formats,
prepare the offline wallet using an offline copy of the chain validated through
activation, then issue and export its fixed public descriptors. Alternatively,
use keys and descriptors already provisioned on the offline side. This tutorial
does not claim a chainless default-address provisioning route for newer formats.
Keep seeds and private keys on the offline host.

### Create and Prepare the `offline_wallet`

1. On the offline machine create a wallet named `offline_wallet` secured by a wallet `passphrase`. This wallet will contain private keys and must remain unconnected to any networks at all times.

```sh
[offline]$ ./build/bin/tidecoin-cli -testnet -named createwallet \
                wallet_name="offline_wallet" \
                passphrase="** enter passphrase **"

{
  "name": "offline_wallet"
}
```

`tidecoin rpc` can also be substituted for `tidecoin-cli`.

> [!NOTE]
> The use of a passphrase is crucial to encrypt the wallet.dat file. This encryption ensures that even if an unauthorized individual gains access to the offline host, they won't be able to access the wallet's contents. Further details about securing your wallet can be found in [Managing Wallets](managing-wallets.md#12-encrypting-the-wallet)

2. Issue a receive address and a change address from the `offline_wallet`.

```sh
[offline]$ RECEIVE=$(./build/bin/tidecoin-cli -testnet -rpcwallet="offline_wallet" getnewaddress "" bech32)
[offline]$ CHANGE=$(./build/bin/tidecoin-cli -testnet -rpcwallet="offline_wallet" getrawchangeaddress bech32)
[offline]$ echo "$RECEIVE $CHANGE"

ttbc1qtar8ynfvqdcvfdspvt7x7u83htlej05l0luvj6 ttbc1qymvagxfujwzuwmn04nttjv6ewyutrwuw80xd5p
```

3. Export the public descriptors of these two addresses to a JSON file named `descriptors.json`. `getaddressinfo` returns, in its `desc` field, a fixed descriptor containing the address's public key and script, with no seed reference and no private key. Export `desc`, not `parent_desc`: the latter refers to the seed and cannot be used without it.

```sh
[offline]$ jq -n \
             --arg receive "$(./build/bin/tidecoin-cli -testnet -rpcwallet="offline_wallet" getaddressinfo "$RECEIVE" | jq -r .desc)" \
             --arg change "$(./build/bin/tidecoin-cli -testnet -rpcwallet="offline_wallet" getaddressinfo "$CHANGE" | jq -r .desc)" \
             '[{desc: $receive, timestamp: "now"}, {desc: $change, timestamp: "now", internal: true}]' \
             > /path/to/descriptors.json
```

> [!NOTE]
> The `descriptors.json` file will be transferred to the online machine (e.g. using a USB flash drive) where it can be imported to create a related watch-only wallet. Each descriptor is roughly two kilobytes or more, because post-quantum public keys are large.

### Create the online `watch_only_wallet`

1. On the online machine create a blank watch-only wallet which has private keys disabled and is named `watch_only_wallet`. This is achieved by using the `createwallet` options: `disable_private_keys=true, blank=true`.

The `watch_only_wallet` wallet will be used to track and validate incoming transactions, create unsigned PSBTs when spending coins, and broadcast signed and finalized PSBTs.

> [!NOTE]
> `disable_private_keys` indicates that the wallet should refuse to import private keys, i.e. will be a dedicated watch-only wallet.

```sh
[online]$ ./build/bin/tidecoin-cli -testnet -named createwallet \
              wallet_name="watch_only_wallet" \
              disable_private_keys=true \
              blank=true

{
  "name": "watch_only_wallet"
}
```

2. Import the public descriptors to the online `watch_only_wallet` using the `descriptors.json` file created on the offline wallet.

```sh
[online]$ ./build/bin/tidecoin-cli -testnet -rpcwallet="watch_only_wallet" importdescriptors "$(cat /path/to/descriptors.json)"

[
  {
    "success": true
  },
  {
    "success": true
  }
]
```
> [!NOTE]
> The two success values are for the receive address and the change address. These are fixed scripts, not an address generator: `getnewaddress` on the `watch_only_wallet` fails with "This wallet has no available keys". To receive or spend again, issue further addresses on the `offline_wallet` and import their descriptors in the same way. When importing an address that may already have received coins, use a `timestamp` from before the first payment so the wallet rescans far enough back.

### Fund the `offline_wallet`

At this point, it's important to understand that both the `offline_wallet` and online `watch_only_wallet` know the public keys of the provisioned addresses. Transactions can be created using either wallet, but valid signatures can only be added by the `offline_wallet` as only it has the private keys.

1. Send a small amount of testnet coins to the receive address issued in the previous section, `ttbc1qtar8ynfvqdcvfdspvt7x7u83htlej05l0luvj6`, for example from another wallet you control.

2. Confirm that coins were received using the online `watch_only_wallet`. Note that the transaction may take a few moments before being received on your local node, depending on its connectivity. Just re-run the command periodically until the transaction is received.

```sh
[online]$ ./build/bin/tidecoin-cli -testnet -rpcwallet="watch_only_wallet" listunspent

[
  {
    "txid": "081988cd4e4bd848007029df343670a514187ca3283deed302a665d51bec06e4",
    "vout": 1,
    "address": "ttbc1qtar8ynfvqdcvfdspvt7x7u83htlej05l0luvj6",
    "label": "",
    "scriptPubKey": "00145f46724d2c0370c4b60162fc6f70f1baff993e9f",
    "amount": 0.01000000,
    "confirmations": 4,
    "spendable": true,
    "solvable": true,
    "desc": "wpkh(07097670b3dacade218820f7d510...5feeff6)#ytf37vwh",
    "parent_descs": [
      "wpkh(07097670b3dacade218820f7d510...5feeff6)#ytf37vwh"
    ],
    "safe": true
  }
]
```

> [!NOTE]
> The Falcon-512 public key in the descriptors is 897 bytes long and is abbreviated with `...` above.

### Create and Export an Unsigned PSBT

1. Get a destination address for the transaction. In this tutorial we'll be sending funds to the address `ttbc1qr97l0yh4v7fvrk7lmd7ddzxpulnx9wgl303wky`.

2. Create a funded but unsigned PSBT to the destination address with the online `watch_only_wallet` by using `send`, and export the unsigned PSBT to a file `funded_psbt.txt` for easy portability to the `offline_wallet` for signing. The `watch_only_wallet` cannot generate a change address, so pass the provisioned one in `change_address`:

```sh
[online]$ ./build/bin/tidecoin-cli -testnet -rpcwallet="watch_only_wallet" -named send \
              outputs='{"ttbc1qr97l0yh4v7fvrk7lmd7ddzxpulnx9wgl303wky": 0.009}' \
              options='{"change_address": "ttbc1qymvagxfujwzuwmn04nttjv6ewyutrwuw80xd5p"}' \
              | jq -r '.psbt' \
              >> /path/to/funded_psbt.txt

[online]$ cat /path/to/funded_psbt.txt

cHNidP8BAHECAAAAAeQG7BvVZaYC0+49KKN8GBSlcDY03ylwAEjYS07NiBkIAQAAAAD9////AgByAQAAAAAAFgAUJtnUGTyThcdub6zWuTNZcTixu46guw0AAAAAABYAFBl995L1Z5LB29/bfNaIwefmYrkfaQAAAAABAHECAAAAARLgulXo1cbJQO1o/EdTkdWpKvXOwsKB8q2uvF9+BLNnAAAAAAD9////AvLRW+4AAAAAFgAU/q6WgCyQEByZPqnqqXJ9DpA9rGNAQg8AAAAAABYAFF9Gck0sA3DEtgFi/G9w8br/mT6fZQAAAAEBH0BCDwAAAAAAFgAUX0ZyTSwDcMS2AWL8b3Dxuv+ZPp8AAAA=
```
> [!NOTE]
> `send` selects the inputs for the transaction automatically from the coins the `watch_only_wallet` can spend.

### Decode and Analyze the Unsigned PSBT

Decode and analyze the unsigned PSBT on the `offline_wallet` using the `funded_psbt.txt` file:

```sh
[offline]$ ./build/bin/tidecoin-cli -testnet decodepsbt $(cat /path/to/funded_psbt.txt)

{
    ...
}

[offline]$ ./build/bin/tidecoin-cli -testnet -named analyzepsbt \
                psbt="$(cat /path/to/funded_psbt.txt)" rules="$RULES"

{
  "inputs": [
    {
      "has_utxo": true,
      "is_final": false,
      "next": "updater",
      "missing": {
        "pubkeys": [
          "5f46724d2c0370c4b60162fc6f70f1baff993e9f"
        ]
      }
    }
  ],
  "rules": "post-auxpow",
  "warnings": ["Explicit post-auxpow script rules differ from the local next-block rules (pre-auxpow). Completion is evaluated using post-auxpow; acceptance must be checked on the destination node."],
  "fee": 0.00005280,
  "next": "updater"
}
```

Notice that the analysis of the PSBT shows that the "pubkeys" of the input are missing, identified by their hash160 "5f46724d2c0370c4b60162fc6f70f1baff993e9f". A Tidecoin PSBT carries an input's public key only together with its signature, so the next step is for the `offline_wallet`, which holds the key, to add both. The size and feerate estimates are omitted until the public key is known.

### Process and Sign the PSBT

1. Unlock the `offline_wallet` with the Passphrase:

Use the walletpassphrase command to unlock the `offline_wallet` with the passphrase. You should specify the passphrase and a timeout (in seconds) for how long you want the wallet to remain unlocked.

```sh
[offline]$ ./build/bin/tidecoin-cli -testnet -rpcwallet="offline_wallet" walletpassphrase "** enter passphrase **" 60
```

2. Process, sign and finalize with the recorded destination rules. Save the
whole response before extracting hex, so incomplete results and notices can be
reviewed:

```sh
[offline]$ ./build/bin/tidecoin-cli -testnet -rpcwallet="offline_wallet" -named walletprocesspsbt \
                psbt="$(cat /path/to/funded_psbt.txt)" rules="$RULES" \
                > /path/to/signing_result.json
[offline]$ jq '{rules, warnings, complete}' /path/to/signing_result.json
[offline]$ jq -er --arg rules "$RULES" \
                'select(.rules == $rules and .complete == true) | .hex // error("No completed transaction")' \
                /path/to/signing_result.json > /path/to/final_tx.txt
```

If processing is incomplete, inspect the PSBT and resolve missing scripts, keys
or previous-output data before proceeding. A legacy input requires the full
previous transaction, including when its final fields are already present.
If finalizing separately, use the same era:

```sh
[offline]$ ./build/bin/tidecoin-cli -testnet -named finalizepsbt \
                psbt="$(jq -r .psbt /path/to/signing_result.json)" rules="$RULES"
```

`complete: true` means the input scripts verify under the selected rules using
the required input data. It does not establish that outputs exist or remain
unspent, or that finality, maturity and fee requirements are met. Existing
partials are checked under these same rules: an owned partial that fails can be
replaced when signing, while an invalid supplied final stays incomplete.

### Check and Broadcast the Signed Transaction

Transfer `final_tx.txt` to the online host. Check it against the destination
node's actual rules before broadcasting; these RPCs have no rule override:

```sh
[online]$ ./build/bin/tidecoin-cli -testnet testmempoolaccept \
               "$(jq -Rn --arg tx "$(cat /path/to/final_tx.txt)" '[$tx]')"
```

Review `allowed` and any rejection reason. If accepted, broadcast:

```sh
[online]$ ./build/bin/tidecoin-cli -testnet sendrawtransaction "$(cat /path/to/final_tx.txt)"
```

A later chain or mempool change can still affect broadcast acceptance.

### Confirm Wallet Balance

Confirm the updated balance of the offline wallet using the `watch_only_wallet`. The balance includes the change, because the change address was imported as well.

```sh
[online]$ ./build/bin/tidecoin-cli -testnet -rpcwallet="watch_only_wallet" getbalances

{
  "mine": {
    "trusted": 0.00094720,
    "untrusted_pending": 0.00000000,
    "immature": 0.00000000
  },
  "lastprocessedblock": {
    "hash": "25a1d0785f7fbf133e695e4181ffb55358e7d0a4e28904dc5856e283138ce38e",
    "height": 106
  }
}
```


You can also show transactions related to the wallet using `listtransactions`

```sh
[online]$ ./build/bin/tidecoin-cli -testnet -rpcwallet="watch_only_wallet" listtransactions

{
    ...
}
```
