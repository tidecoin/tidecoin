# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(generate_setup_nsi)
  set(abs_top_srcdir ${PROJECT_SOURCE_DIR})
  set(abs_top_builddir ${PROJECT_BINARY_DIR})
  set(CLIENT_URL ${PROJECT_HOMEPAGE_URL})
  set(CLIENT_TARNAME "tidecoin")
  set(TIDECOIN_WRAPPER_NAME "tidecoin")
  set(TIDECOIN_GUI_NAME "tidecoin-qt")
  set(TIDECOIN_DAEMON_NAME "tidecoind")
  set(TIDECOIN_CLI_NAME "tidecoin-cli")
  set(TIDECOIN_TX_NAME "tidecoin-tx")
  set(TIDECOIN_WALLET_TOOL_NAME "tidecoin-wallet")
  set(TIDECOIN_TEST_NAME "test_tidecoin")
  set(EXEEXT ${CMAKE_EXECUTABLE_SUFFIX})
  configure_file(${PROJECT_SOURCE_DIR}/share/setup.nsi.in ${PROJECT_BINARY_DIR}/tidecoin-win64-setup.nsi USE_SOURCE_PERMISSIONS @ONLY)
endfunction()
