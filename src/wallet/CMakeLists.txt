# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Wallet functionality used by tidecoind and tidecoin-wallet executables.
add_library(tidecoin_wallet STATIC EXCLUDE_FROM_ALL
  coincontrol.cpp
  coinselection.cpp
  context.cpp
  crypter.cpp
  db.cpp
  dump.cpp
  external_signer_scriptpubkeyman.cpp
  feebumper.cpp
  fees.cpp
  interfaces.cpp
  load.cpp
  migrate.cpp
  receive.cpp
  rpc/addresses.cpp
  rpc/backup.cpp
  rpc/coins.cpp
  rpc/encrypt.cpp
  rpc/getauxrpc.cpp
  rpc/signmessage.cpp
  rpc/spend.cpp
  rpc/transactions.cpp
  rpc/util.cpp
  rpc/wallet.cpp
  scriptpubkeyman.cpp
  spend.cpp
  sqlite.cpp
  transaction.cpp
  wallet.cpp
  walletdb.cpp
  walletutil.cpp
)

set(wallet_sqlite_target "")
foreach(sqlite_target IN ITEMS unofficial::sqlite3::sqlite3 SQLite3::SQLite3 SQLite::SQLite3)
  if(TARGET ${sqlite_target})
    set(wallet_sqlite_target ${sqlite_target})
    break()
  endif()
endforeach()
if(NOT wallet_sqlite_target)
  message(FATAL_ERROR "SQLite target not found")
endif()

target_link_libraries(tidecoin_wallet
  PRIVATE
    core_interface
    tidecoin_common
    ${wallet_sqlite_target}
    univalue
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
)
