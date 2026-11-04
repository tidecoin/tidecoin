# Managing the Wallet

## 1. Backing Up and Restoring The Wallet

### 1.1 Creating the Wallet

Tidecoin does not create a default wallet automatically.
Wallets can be created with the `createwallet` RPC or with the `Create wallet` GUI menu item.

In the GUI, the `Create a new wallet` button is displayed on the main screen when there is no wallet loaded. Alternatively, there is the option `File` ->`Create wallet`.

The following command, for example, creates a descriptor wallet. More information about this command may be found by running `tidecoin-cli help createwallet`.

```
$ tidecoin-cli createwallet "wallet-01"
```

`tidecoin rpc` can also be used as a newer alternative for named RPC calls.

By default, wallets are created in the `wallets` folder of the data directory, which varies by operating system, as shown below. The user can change the default by using the `-datadir` or `-walletdir` initialization parameters.

| Operating System | Default wallet directory                                    |
| -----------------|:------------------------------------------------------------|
| Linux            | `/home/<user>/.tidecoin/wallets`                             |
| Windows          | `C:\Users\<user>\AppData\Local\Tidecoin\wallets`             |
| macOS            | `/Users/<user>/Library/Application Support/Tidecoin/wallets` |

On Windows, Tidecoin also supports a legacy data directory at
`C:\Users\<user>\AppData\Roaming\Tidecoin` and will keep using it if it already exists.

### 1.2 Encrypting the Wallet

The `wallet.dat` file is not encrypted by default and is, therefore, vulnerable if an attacker gains access to the device where the wallet or the backups are stored.

Wallet encryption may prevent unauthorized access. However, this significantly increases the risk of losing coins due to forgotten passphrases. There is no way to recover a passphrase. This tradeoff should be well thought out by the user.

Wallet encryption may also not protect against more sophisticated attacks. An attacker can, for example, obtain the password by installing a keylogger on the user's machine.

Make a new wallet backup after encryption. Successful encryption of a non-blank
wallet sets up a fresh PQHD seed and default descriptors for future addresses;
existing keys and descriptors remain available for earlier addresses. A backup
made before this setup does not contain the new seed. Encrypting a blank wallet
does not generate a seed or descriptors; any existing seed and policy are retained.

If encryption succeeds but replacement-seed setup fails, the error says that the
wallet is encrypted and locked and that its existing active descriptors remain
in use. No replacement seed was installed. Follow the
[PQHD recovery instructions](pq-rpc.md#createpqhdseed) after resolving the write
error, then make a new backup.

Changing the passphrase does not replace the existing seeds or keys. Back up
after the change to save the new encryption settings. Earlier encrypted backups
still use their original passphrase, and earlier unencrypted backups remain
unencrypted. Those backups retain their old keys; they do not become useless.
Keep them until you have verified the new backup.

The wallet's private key may be encrypted with the following command:

```
$ tidecoin-cli -rpcwallet="wallet-01" encryptwallet "passphrase"
```

Once encrypted, the passphrase can be changed with the `walletpassphrasechange` command.

```
$ tidecoin-cli -rpcwallet="wallet-01" walletpassphrasechange "oldpassphrase" "newpassphrase"
```

The argument passed to `-rpcwallet` is the name of the wallet to be encrypted.

Only the wallet's private key is encrypted. All other wallet information, such as transactions, is still visible.

The wallet's private key can also be encrypted in the `createwallet` command via the `passphrase` argument:

```
$ tidecoin-cli -named createwallet wallet_name="wallet-01" passphrase="passphrase"
```

Note that if the passphrase is lost, all the coins in the wallet will also be lost forever.

### 1.3 Unlocking the Wallet

If the wallet is encrypted and the user tries any operation related to private keys, such as sending coins, an error message will be displayed.

```
$ tidecoin-cli -rpcwallet="wallet-01" sendtoaddress "<recipient_address>" 0.01
error code: -13
error message:
Error: Please enter the wallet passphrase with walletpassphrase first.
```

To unlock the wallet and allow it to run these operations, the `walletpassphrase` RPC is required.

This command takes the passphrase and an argument called `timeout`, which specifies the time in seconds that the wallet decryption key is stored in memory. After this period expires, the user needs to execute this RPC again.

```
$ tidecoin-cli -rpcwallet="wallet-01" walletpassphrase "passphrase" 120
```

In the GUI, there is no specific menu item to unlock the wallet. When the user sends coins, the passphrase will be prompted automatically.

### 1.4 Backing Up the Wallet

To backup the wallet, the `backupwallet` RPC or the `Backup Wallet` GUI menu item must be used to ensure the file is in a safe state when the copy is made.

In the RPC, the destination parameter must include the name of the file. Otherwise, the command will return an error message like "Error: Wallet backup failed!".

```
$ tidecoin-cli -rpcwallet="wallet-01" backupwallet /home/node01/Backups/backup-01.dat
```

In the GUI, the wallet is selected in the `Wallet` drop-down list in the upper right corner. If this list is not present, the wallet can be loaded in `File` ->`Open Wallet` if necessary. Then, the backup can be done in `File` -> `Backup Wallet…`.

This backup file can be stored on one or multiple offline devices, which must be reliable enough to work in an emergency and be malware free. Backup files can be regularly tested to avoid problems in the future.

If the computer has malware, it can compromise the wallet when recovering the backup file. One way to minimize this is to not connect the backup to an online device.

If both the wallet and all backups are lost for any reason, the coins related to this wallet will become permanently inaccessible.

### 1.5 Backup Frequency

Historically, non-HD wallets were collections of unrelated private keys. If such a wallet received funds to a newly generated address and was later restored from an older backup, funds sent to that newer address could be lost because there was no deterministic derivation path to recreate it.

Modern Tidecoin wallets use PQHD derivation for default addresses. A complete
wallet backup preserves the seeds, descriptors and derivation state saved at
that time. It does not contain seeds, imported keys or descriptors added later.
Make a new backup after adding or selecting a seed, importing keys or
descriptors, encrypting, changing the passphrase, or migrating a legacy wallet.
A seed identifier alone is not a seed backup.

Back up regularly to retain recent labels and other wallet metadata, which a
blockchain rescan cannot reconstruct. For legacy wallets without deterministic
derivation, back up whenever new keys are generated or imported; an older backup
may not contain them. Verify that you can restore a backup before relying on it.

### 1.6 Restoring the Wallet From a Backup

To restore a wallet, the `restorewallet` RPC or the `Restore Wallet` GUI menu item (`File` -> `Restore Wallet…`) must be used.

```
$ tidecoin-cli restorewallet "restored-wallet" /home/node01/Backups/backup-01.dat
```

After that, `getwalletinfo` can be used to check if the wallet has been fully restored.

```
$ tidecoin-cli -rpcwallet="restored-wallet" getwalletinfo
```

The restored wallet can also be loaded in the GUI via `File` ->`Open wallet`.

## Wallet Passphrase

Understanding wallet security is crucial for safely storing your Tidecoin. A key aspect is the wallet passphrase, used for encryption. Let's explore its nuances, role, encryption process, and limitations.

- **Not the Seed:**
The wallet passphrase and the seed are two separate components in wallet security. The seed, or HD seed, functions as a master key for deriving private and public keys in a hierarchical deterministic (HD) wallet. In contrast, the passphrase serves as an additional layer of security specifically designed to secure the private keys within the wallet. The passphrase serves as a safeguard, demanding an additional layer of authentication to access funds in the wallet.

- **Protection Against Unauthorized Access:**
The passphrase serves as a protective measure, securing your funds in situations where an unauthorized user gains access to your unlocked computer or device while your wallet application is active. Without the passphrase, they would be unable to access your wallet's funds or execute transactions. However, it's essential to be aware that someone with access can potentially compromise the security of your passphrase by installing a keylogger.

- **Doesn't Encrypt Metadata or Public Keys:**
It's important to note that the passphrase primarily secures the private keys and access to funds within the wallet. It does not encrypt metadata associated with transactions or public keys. Information about your transaction history and the public keys involved may still be visible.

- **Risk of Fund Loss if Forgotten or Lost:**
If the wallet passphrase is too complex and is subsequently forgotten or lost, there is a risk of losing access to the funds permanently. A forgotten passphrase will result in the inability to unlock the wallet and access the funds.

## Migrating Legacy Wallets to Descriptor Wallets

Legacy Tidecoin Berkeley DB wallets (traditional non-descriptor wallets) can be migrated to become descriptor wallets
through the use of the `migratewallet` RPC. Migrated wallets will have all of their addresses and private keys added to
a newly created Descriptor wallet that has the same name as the original wallet. As Descriptor
wallets do not support having both private keys and watch-only scripts, there may be up to two
additional wallets created after migration. In addition to a descriptor wallet of the same name,
there may also be a wallet named `<name>_watchonly` and `<name>_solvables`. `<name>_watchonly`
contains all of the watchonly scripts. `<name>_solvables` contains any scripts that the wallet
knows but for which it is not watching the corresponding P2(W)SH scripts. If the legacy wallet
contains only watch-only scripts and no private keys, then only the `<name>_watchonly` wallet
will be created and the descriptor wallet with the same name will not be created. Additionally,
the created watch-only descriptor wallet will not have private keys enabled.

Migration preserves existing private keys in explicit `combo(...)` descriptors,
so the addresses controlled by those keys keep the same keys. When migrating
spendable key material, the wallet also creates a fresh PQHD seed and default
descriptors for future receive and change addresses. Watch-only migration does
not create private seeds. This does not reuse a BIP32 seed or derive keys using
BIP44/49/84/86 paths.

Make a new backup of every resulting wallet, including any watch-only or solvable
wallet. Keep the original legacy backup as well. It preserves the original keys
but does not contain the fresh PQHD seed or the new descriptor-wallet state.

Given that there is an extremely large number of possible configurations for the scripts that
Legacy wallets can know about, be watching for, and be able to sign for, `migratewallet` only
makes a best effort attempt to capture all of these things into Descriptor wallets. There may be
unforeseen configurations which result in some scripts being excluded. If a migration fails
unexpectedly or otherwise misses any scripts, please create an issue on GitHub. A backup of the
original wallet is created in the wallet directory with a `.legacy.bak` suffix;
the RPC's `backup_path` result gives its exact location.

The [restore procedure above](#16-restoring-the-wallet-from-a-backup) applies to
the new descriptor-wallet backups. To retry migration from a legacy backup,
stop the node and copy the backup, keeping the original unchanged, into a new,
unused directory under the wallet directory as `<new_name>/wallet.dat`. Restart
without trying to load that legacy wallet, then call `migratewallet` with
`<new_name>` and its passphrase if encrypted. Legacy wallets must be migrated
before they can be loaded; `restorewallet` does not perform that migration.
