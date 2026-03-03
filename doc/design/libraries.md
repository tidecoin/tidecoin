# Libraries

| Name                     | Description |
|--------------------------|-------------|
| *libtidecoin_cli*         | RPC client functionality used by *tidecoin-cli* executable |
| *libtidecoin_common*      | Home for common functionality shared by different executables and libraries. Similar to *libtidecoin_util*, but higher-level (see [Dependencies](#dependencies)). |
| *libtidecoin_consensus*   | Consensus functionality used by *libtidecoin_node* and *libtidecoin_wallet*. |
| *libtidecoin_crypto*      | Hardware-optimized functions for data encryption, hashing, message authentication, and key derivation. |
| *libtidecoin_kernel*      | Consensus engine and support library used for validation by *libtidecoin_node*. |
| *libtidecoinqt*           | GUI functionality used by *tidecoin-qt* and *tidecoin-gui* executables. |
| *libtidecoin_ipc*         | IPC functionality used by *tidecoin-node* and *tidecoin-gui* executables to communicate when [`-DENABLE_IPC=ON`](multiprocess.md) is used. |
| *libtidecoin_node*        | P2P and RPC server functionality used by *tidecoind* and *tidecoin-qt* executables. |
| *libtidecoin_util*        | Home for common functionality shared by different executables and libraries. Similar to *libtidecoin_common*, but lower-level (see [Dependencies](#dependencies)). |
| *libtidecoin_wallet*      | Wallet functionality used by *tidecoind* and *tidecoin-wallet* executables. |
| *libtidecoin_wallet_tool* | Lower-level wallet functionality used by *tidecoin-wallet* executable. |
| *libtidecoin_zmq*         | [ZeroMQ](../zmq.md) functionality used by *tidecoind* and *tidecoin-qt* executables. |

## Conventions

- Most libraries are internal libraries and have APIs which are completely unstable! There are few or no restrictions on backwards compatibility or rules about external dependencies. An exception is *libtidecoin_kernel*, which, at some future point, will have a documented external interface.

- Generally each library should have a corresponding source directory and namespace. Source code organization is a work in progress, so it is true that some namespaces are applied inconsistently, and if you look at [`add_library(tidecoin_* ...)`](../../src/CMakeLists.txt) lists you can see that many libraries pull in files from outside their source directory. But when working with libraries, it is good to follow a consistent pattern like:

  - *libtidecoin_node* code lives in `src/node/` in the `node::` namespace
  - *libtidecoin_wallet* code lives in `src/wallet/` in the `wallet::` namespace
  - *libtidecoin_ipc* code lives in `src/ipc/` in the `ipc::` namespace
  - *libtidecoin_util* code lives in `src/util/` in the `util::` namespace
  - *libtidecoin_consensus* code lives in `src/consensus/` in the `Consensus::` namespace

## Dependencies

- Libraries should minimize what other libraries they depend on, and only reference symbols following the arrows shown in the dependency graph below:

<table><tr><td>

```mermaid

%%{ init : { "flowchart" : { "curve" : "basis" }}}%%

graph TD;

tidecoin-cli[tidecoin-cli]-->libtidecoin_cli;

tidecoind[tidecoind]-->libtidecoin_node;
tidecoind[tidecoind]-->libtidecoin_wallet;

tidecoin-qt[tidecoin-qt]-->libtidecoin_node;
tidecoin-qt[tidecoin-qt]-->libtidecoinqt;
tidecoin-qt[tidecoin-qt]-->libtidecoin_wallet;

tidecoin-wallet[tidecoin-wallet]-->libtidecoin_wallet;
tidecoin-wallet[tidecoin-wallet]-->libtidecoin_wallet_tool;

libtidecoin_cli-->libtidecoin_util;
libtidecoin_cli-->libtidecoin_common;

libtidecoin_consensus-->libtidecoin_crypto;

libtidecoin_common-->libtidecoin_consensus;
libtidecoin_common-->libtidecoin_crypto;
libtidecoin_common-->libtidecoin_util;

libtidecoin_kernel-->libtidecoin_consensus;
libtidecoin_kernel-->libtidecoin_crypto;
libtidecoin_kernel-->libtidecoin_util;

libtidecoin_node-->libtidecoin_consensus;
libtidecoin_node-->libtidecoin_crypto;
libtidecoin_node-->libtidecoin_kernel;
libtidecoin_node-->libtidecoin_common;
libtidecoin_node-->libtidecoin_util;

libtidecoinqt-->libtidecoin_common;
libtidecoinqt-->libtidecoin_util;

libtidecoin_util-->libtidecoin_crypto;

libtidecoin_wallet-->libtidecoin_common;
libtidecoin_wallet-->libtidecoin_crypto;
libtidecoin_wallet-->libtidecoin_util;

libtidecoin_wallet_tool-->libtidecoin_wallet;
libtidecoin_wallet_tool-->libtidecoin_util;

classDef bold stroke-width:2px, font-weight:bold, font-size: smaller;
class tidecoin-qt,tidecoind,tidecoin-cli,tidecoin-wallet bold
```
</td></tr><tr><td>

**Dependency graph**. Arrows show linker symbol dependencies. *Crypto* lib depends on nothing. *Util* lib is depended on by everything. *Kernel* lib depends only on consensus, crypto, and util.

</td></tr></table>

- The graph shows what _linker symbols_ (functions and variables) from each library other libraries can call and reference directly, but it is not a call graph. For example, there is no arrow connecting *libtidecoin_wallet* and *libtidecoin_node* libraries, because these libraries are intended to be modular and not depend on each other's internal implementation details. But wallet code is still able to call node code indirectly through the `interfaces::Chain` abstract class in [`interfaces/chain.h`](../../src/interfaces/chain.h) and node code calls wallet code through the `interfaces::ChainClient` and `interfaces::Chain::Notifications` abstract classes in the same file. In general, defining abstract classes in [`src/interfaces/`](../../src/interfaces/) can be a convenient way of avoiding unwanted direct dependencies or circular dependencies between libraries.

- *libtidecoin_crypto* should be a standalone dependency that any library can depend on, and it should not depend on any other libraries itself.

- *libtidecoin_consensus* should only depend on *libtidecoin_crypto*, and all other libraries besides *libtidecoin_crypto* should be allowed to depend on it.

- *libtidecoin_util* should be a standalone dependency that any library can depend on, and it should not depend on other libraries except *libtidecoin_crypto*. It provides basic utilities that fill in gaps in the C++ standard library and provide lightweight abstractions over platform-specific features. Since the util library is distributed with the kernel and is usable by kernel applications, it shouldn't contain functions that external code shouldn't call, like higher level code targeted at the node or wallet. (*libtidecoin_common* is a better place for higher level code, or code that is meant to be used by internal applications only.)

- *libtidecoin_common* is a home for miscellaneous shared code used by different Tidecoin Core applications. It should not depend on anything other than *libtidecoin_util*, *libtidecoin_consensus*, and *libtidecoin_crypto*.

- *libtidecoin_kernel* should only depend on *libtidecoin_util*, *libtidecoin_consensus*, and *libtidecoin_crypto*.

- The only thing that should depend on *libtidecoin_kernel* internally should be *libtidecoin_node*. GUI and wallet libraries *libtidecoinqt* and *libtidecoin_wallet* in particular should not depend on *libtidecoin_kernel* and the unneeded functionality it would pull in, like block validation. To the extent that GUI and wallet code need scripting and signing functionality, they should be able to get it from *libtidecoin_consensus*, *libtidecoin_common*, *libtidecoin_crypto*, and *libtidecoin_util*, instead of *libtidecoin_kernel*.

- GUI, node, and wallet code internal implementations should all be independent of each other, and the *libtidecoinqt*, *libtidecoin_node*, *libtidecoin_wallet* libraries should never reference each other's symbols. They should only call each other through [`src/interfaces/`](../../src/interfaces/) abstract interfaces.

## Work in progress

- Validation code is moving from *libtidecoin_node* to *libtidecoin_kernel*
