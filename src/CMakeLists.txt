# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(AddWindowsResources)

configure_file(${PROJECT_SOURCE_DIR}/cmake/tidecoin-build-config.h.in tidecoin-build-config.h USE_SOURCE_PERMISSIONS @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

#=============================
# Subprojects
#=============================
# Subprojects include subdirectories that do or could have tests
# and/or benchmark binaries, such as all subtrees and univalue.
# These need to be included before CMAKE_*_OUTPUT_DIRECTORY variables
# are set, so output locations of subproject tests and libraries are
# not overridden.
include(../cmake/crc32c.cmake)
include(../cmake/leveldb.cmake)
include(../cmake/minisketch.cmake)
add_subdirectory(univalue)
if (ENABLE_IPC AND NOT WITH_EXTERNAL_LIBMULTIPROCESS)
  include(../cmake/libmultiprocess.cmake)
  add_libmultiprocess(ipc/libmultiprocess)
endif()

# Set top-level target output locations.
if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()

add_custom_target(generate_build_info
  BYPRODUCTS ${PROJECT_BINARY_DIR}/src/tidecoin-build-info.h
  COMMAND ${CMAKE_COMMAND} -DBUILD_INFO_HEADER_PATH=${PROJECT_BINARY_DIR}/src/tidecoin-build-info.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
  COMMENT "Generating tidecoin-build-info.h"
  VERBATIM
)
add_library(tidecoin_clientversion STATIC EXCLUDE_FROM_ALL
  clientversion.cpp
)
target_link_libraries(tidecoin_clientversion
  PRIVATE
    core_interface
)
add_dependencies(tidecoin_clientversion generate_build_info)

add_subdirectory(crypto)
add_subdirectory(util)
add_subdirectory(pq)
if(ENABLE_IPC)
  add_subdirectory(ipc)
endif()

add_library(tidecoin_consensus STATIC EXCLUDE_FROM_ALL
  arith_uint256.cpp
  consensus/merkle.cpp
  consensus/tx_check.cpp
  hash.cpp
  primitives/block.cpp
  primitives/pureheader.cpp
  primitives/transaction.cpp
  pubkey.cpp
  script/interpreter.cpp
  script/script.cpp
  script/script_error.cpp
  uint256.cpp
)
target_link_libraries(tidecoin_consensus
  PRIVATE
    core_interface
    tidecoin_crypto
  PUBLIC
    tidecoin_quantum
)

if(WITH_ZMQ)
  add_subdirectory(zmq)
endif()

# Home for common functionality shared by different executables and libraries.
# Similar to `tidecoin_util` library, but higher-level.
add_library(tidecoin_common STATIC EXCLUDE_FROM_ALL
  addresstype.cpp
  auxpow.cpp
  base58.cpp
  bech32.cpp
  chain.cpp
  chainparams.cpp
  chainparamsbase.cpp
  coins.cpp
  common/args.cpp
  common/bloom.cpp
  common/config.cpp
  common/init.cpp
  common/interfaces.cpp
  common/messages.cpp
  common/netif.cpp
  common/pcp.cpp
  common/run_command.cpp
  common/settings.cpp
  common/signmessage.cpp
  common/system.cpp
  common/url.cpp
  compressor.cpp
  core_read.cpp
  core_write.cpp
  deploymentinfo.cpp
  external_signer.cpp
  init/common.cpp
  kernel/chainparams.cpp
  key.cpp
  key_io.cpp
  merkleblock.cpp
  net_permissions.cpp
  net_types.cpp
  netaddress.cpp
  netbase.cpp
  outputtype.cpp
  policy/feerate.cpp
  policy/policy.cpp
  pow.cpp
  protocol.cpp
  psbt.cpp
  pq/kem.cpp
  pq/pqhd_kdf.cpp
  pq/pqhd_keygen.cpp
  rpc/rawtransaction_util.cpp
  rpc/request.cpp
  rpc/util.cpp
  scheduler.cpp
  script/descriptor.cpp
  script/miniscript.cpp
  script/parsing.cpp
  script/sign.cpp
  script/signingprovider.cpp
  script/solver.cpp
)
target_link_libraries(tidecoin_common
  PRIVATE
    core_interface
    tidecoin_consensus
    tidecoin_crypto
    tidecoin_util
    univalue
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
    $<$<PLATFORM_ID:Windows>:ws2_32>
  PUBLIC
    tidecoin_quantum
)

include(InstallBinaryComponent)

if(ENABLE_WALLET)
  add_subdirectory(wallet)

  if(BUILD_WALLET_TOOL)
    add_executable(tidecoin-wallet
      tidecoin-wallet.cpp
      init/tidecoin-wallet.cpp
      wallet/wallettool.cpp
    )
    set_target_properties(tidecoin-wallet PROPERTIES OUTPUT_NAME tidecoin-wallet)
    add_windows_resources(tidecoin-wallet tidecoin-wallet-res.rc)
    add_windows_application_manifest(tidecoin-wallet)
    target_link_libraries(tidecoin-wallet
      core_interface
      tidecoin_wallet
      tidecoin_node
      tidecoin_common
      tidecoin_util
      Boost::headers
    )
    install_binary_component(tidecoin-wallet HAS_MANPAGE)
  endif()
endif()


# P2P and RPC server functionality used by `tidecoind` and `tidecoin-qt` executables.
add_library(tidecoin_node STATIC EXCLUDE_FROM_ALL
  addrdb.cpp
  addrman.cpp
  banman.cpp
  bip324_pq.cpp
  blockencodings.cpp
  blockfilter.cpp
  consensus/tx_verify.cpp
  dbwrapper.cpp
  deploymentstatus.cpp
  flatfile.cpp
  headerssync.cpp
  httprpc.cpp
  httpserver.cpp
  i2p.cpp
  index/base.cpp
  index/blockfilterindex.cpp
  index/coinstatsindex.cpp
  index/txindex.cpp
  init.cpp
  kernel/chain.cpp
  kernel/checks.cpp
  kernel/coinstats.cpp
  kernel/context.cpp
  kernel/cs_main.cpp
  kernel/disconnected_transactions.cpp
  kernel/mempool_removal_reason.cpp
  mapport.cpp
  net.cpp
  net_processing.cpp
  netgroup.cpp
  node/abort.cpp
  node/blockmanager_args.cpp
  node/blockstorage.cpp
  node/caches.cpp
  node/chainstate.cpp
  node/chainstatemanager_args.cpp
  node/coin.cpp
  node/coins_view_args.cpp
  node/connection_types.cpp
  node/context.cpp
  node/database_args.cpp
  node/eviction.cpp
  node/interface_ui.cpp
  node/interfaces.cpp
  node/kernel_notifications.cpp
  node/mempool_args.cpp
  node/mempool_persist.cpp
  node/mempool_persist_args.cpp
  node/miner.cpp
  node/mini_miner.cpp
  node/minisketchwrapper.cpp
  node/peerman_args.cpp
  node/psbt.cpp
  node/timeoffsets.cpp
  node/transaction.cpp
  node/txdownloadman_impl.cpp
  node/txorphanage.cpp
  node/txreconciliation.cpp
  node/utxo_snapshot.cpp
  node/warnings.cpp
  noui.cpp
  policy/ephemeral_policy.cpp
  policy/fees.cpp
  policy/fees_args.cpp
  policy/packages.cpp
  policy/rbf.cpp
  policy/settings.cpp
  policy/truc_policy.cpp
  rest.cpp
  rpc/blockchain.cpp
  rpc/auxpow_miner.cpp
  rpc/external_signer.cpp
  rpc/fees.cpp
  rpc/mempool.cpp
  rpc/mining.cpp
  rpc/net.cpp
  rpc/node.cpp
  rpc/output_script.cpp
  rpc/rawtransaction.cpp
  rpc/server.cpp
  rpc/server_util.cpp
  rpc/signmessage.cpp
  rpc/txoutproof.cpp
  script/sigcache.cpp
  torcontrol.cpp
  txdb.cpp
  txgraph.cpp
  txmempool.cpp
  txrequest.cpp
  validation.cpp
  validationinterface.cpp
  versionbits.cpp
  $<$<TARGET_EXISTS:tidecoin_wallet>:wallet/init.cpp>
  $<$<NOT:$<TARGET_EXISTS:tidecoin_wallet>>:dummywallet.cpp>
)
target_link_libraries(tidecoin_node
  PRIVATE
    core_interface
    tidecoin_common
    tidecoin_util
    $<TARGET_NAME_IF_EXISTS:tidecoin_zmq>
    leveldb
    minisketch
    univalue
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
)

# Bitcoin wrapper executable that can call other executables.
if(BUILD_TIDECOIN_BIN)
  add_executable(tidecoin tidecoin.cpp)
  set_target_properties(tidecoin PROPERTIES OUTPUT_NAME tidecoin)
  add_windows_resources(tidecoin tidecoin-res.rc)
  add_windows_application_manifest(tidecoin)
  target_link_libraries(tidecoin core_interface tidecoin_util)
  install_binary_component(tidecoin HAS_MANPAGE)
endif()

# Tidecoin daemon.
if(BUILD_DAEMON)
  add_executable(tidecoind
    tidecoind.cpp
    init/tidecoind.cpp
  )
  set_target_properties(tidecoind PROPERTIES OUTPUT_NAME tidecoind)
  add_windows_resources(tidecoind tidecoind-res.rc)
  add_windows_application_manifest(tidecoind)
  target_link_libraries(tidecoind
    core_interface
    tidecoin_node
    $<TARGET_NAME_IF_EXISTS:tidecoin_wallet>
  )
  install_binary_component(tidecoind HAS_MANPAGE)
endif()
if(ENABLE_IPC AND BUILD_DAEMON)
  add_executable(tidecoin-node
    tidecoind.cpp
    init/tidecoin-node.cpp
  )
  set_target_properties(tidecoin-node PROPERTIES OUTPUT_NAME tidecoin-node)
  target_link_libraries(tidecoin-node
    core_interface
    tidecoin_node
    tidecoin_ipc
    $<TARGET_NAME_IF_EXISTS:tidecoin_wallet>
  )
  install_binary_component(tidecoin-node INTERNAL)
endif()

if(ENABLE_IPC AND BUILD_TESTS)
    # tidecoin_ipc_test library target is defined here in src/CMakeLists.txt
    # instead of src/test/CMakeLists.txt so capnp files in src/test/ are able to
    # reference capnp files in src/ipc/capnp/ by relative path. The Cap'n Proto
    # compiler only allows importing by relative path when the importing and
    # imported files are underneath the same compilation source prefix, so the
    # source prefix must be src/, not src/test/
    add_library(tidecoin_ipc_test STATIC EXCLUDE_FROM_ALL
      test/ipc_test.cpp
    )
    target_capnp_sources(tidecoin_ipc_test ${PROJECT_SOURCE_DIR}
      test/ipc_test.capnp
    )
    add_dependencies(tidecoin_ipc_test tidecoin_ipc_headers)
endif()


add_library(tidecoin_cli STATIC EXCLUDE_FROM_ALL
  compat/stdin.cpp
  rpc/client.cpp
)
target_link_libraries(tidecoin_cli
  PUBLIC
    core_interface
    univalue
)


# Bitcoin Core RPC client
if(BUILD_CLI)
  add_executable(tidecoin-cli tidecoin-cli.cpp)
  set_target_properties(tidecoin-cli PROPERTIES OUTPUT_NAME tidecoin-cli)
  add_windows_resources(tidecoin-cli tidecoin-cli-res.rc)
  add_windows_application_manifest(tidecoin-cli)
  target_link_libraries(tidecoin-cli
    core_interface
    tidecoin_cli
    tidecoin_common
    tidecoin_util
    libevent::core
    libevent::extra
  )
  install_binary_component(tidecoin-cli HAS_MANPAGE)
endif()


if(BUILD_TX)
  add_executable(tidecoin-tx tidecoin-tx.cpp)
  set_target_properties(tidecoin-tx PROPERTIES OUTPUT_NAME tidecoin-tx)
  add_windows_resources(tidecoin-tx tidecoin-tx-res.rc)
  add_windows_application_manifest(tidecoin-tx)
  target_link_libraries(tidecoin-tx
    core_interface
    tidecoin_common
    tidecoin_util
    univalue
  )
  install_binary_component(tidecoin-tx HAS_MANPAGE)
endif()


if(BUILD_UTIL)
  add_executable(tidecoin-util tidecoin-util.cpp)
  set_target_properties(tidecoin-util PROPERTIES OUTPUT_NAME tidecoin-util)
  add_windows_resources(tidecoin-util tidecoin-util-res.rc)
  add_windows_application_manifest(tidecoin-util)
  target_link_libraries(tidecoin-util
    core_interface
    tidecoin_common
    tidecoin_util
  )
  install_binary_component(tidecoin-util HAS_MANPAGE)
endif()


if(BUILD_GUI)
  add_subdirectory(qt)
endif()


if(BUILD_KERNEL_LIB)
  add_subdirectory(kernel)
endif()

if(BUILD_UTIL_CHAINSTATE)
  add_executable(tidecoin-chainstate
    tidecoin-chainstate.cpp
  )
  set_target_properties(tidecoin-chainstate PROPERTIES OUTPUT_NAME tidecoin-chainstate)
  # TODO: The `SKIP_BUILD_RPATH` property setting can be deleted
  #       in the future after reordering Guix script commands to
  #       perform binary checks after the installation step.
  # Relevant discussions:
  # - https://github.com/hebasto/bitcoin/pull/236#issuecomment-2183120953
  # - https://github.com/bitcoin/bitcoin/pull/30312#issuecomment-2191235833
  set_target_properties(tidecoin-chainstate PROPERTIES
    SKIP_BUILD_RPATH OFF
  )
  target_link_libraries(tidecoin-chainstate
    PRIVATE
      core_interface
      tidecoinkernel
  )
  install_binary_component(tidecoin-chainstate INTERNAL)
endif()


add_subdirectory(test/util)
if(BUILD_BENCH)
  add_subdirectory(bench)
endif()

if(BUILD_TESTS)
  add_subdirectory(test)
endif()

if(BUILD_FUZZ_BINARY)
  add_subdirectory(test/fuzz)
endif()
