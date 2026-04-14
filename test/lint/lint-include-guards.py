#!/usr/bin/env python3
#
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Check include guards.
"""

import re
import sys
from subprocess import check_output

from lint_ignore_dirs import SHARED_EXCLUDED_SUBTREES


HEADER_ID_PREFIXES = ['BITCOIN_', 'TIDECOIN_']
HEADER_ID_SUFFIX = '_H'

EXCLUDE_FILES_WITH_PREFIX = ['contrib/devtools/tidecoin-tidy',
                             'src/crypto/scrypt.h',
                             'src/crypto/ctaes',
                             'src/crypto/yespower/',
                             'src/pq/falcon-1024/',
                             'src/pq/falcon-512/',
                             'src/pq/compat.h',
                             'src/pq/fips202.h',
                             'src/pq/ml-dsa-44/',
                             'src/pq/ml-dsa-65/',
                             'src/pq/ml-dsa-87/',
                             'src/pq/ml-kem-512/',
                             'src/tinyformat.h',
                             'src/bench/nanobench.h',
                             'src/test/fuzz/FuzzedDataProvider.h'] + SHARED_EXCLUDED_SUBTREES


def _get_header_file_lst() -> list[str]:
    """ Helper function to get a list of header filepaths to be
        checked for include guards.
    """
    git_cmd_lst = ['git', 'ls-files', '--', '*.h']
    header_file_lst = check_output(
        git_cmd_lst).decode('utf-8').splitlines()

    header_file_lst = [hf for hf in header_file_lst
                       if not any(ef in hf for ef
                                  in EXCLUDE_FILES_WITH_PREFIX)]

    return header_file_lst


def _get_header_ids(header_file: str) -> list[str]:
    """ Helper function to get the header id from a header file
        string.

        eg: 'src/wallet/walletdb.h' -> 'BITCOIN_WALLET_WALLETDB_H'

    Args:
        header_file: Filepath to header file.

    Returns:
        The accepted header ids.
    """
    header_id_base = header_file.split('/')[1:]
    header_id_base = '_'.join(header_id_base)
    header_id_base = header_id_base.replace('.h', '').replace('-', '_')
    header_id_base = header_id_base.upper()

    header_ids = [f'{prefix}{header_id_base}{HEADER_ID_SUFFIX}' for prefix in HEADER_ID_PREFIXES]

    return header_ids


def main():
    exit_code = 0

    header_file_lst = _get_header_file_lst()
    for header_file in header_file_lst:
        header_ids = _get_header_ids(header_file)

        with open(header_file, 'r', encoding='utf-8') as f:
            header_file_contents = f.readlines()

        count = 0
        for header_id in header_ids:
            regex_pattern = f'^#(ifndef|define|endif //) {header_id}'
            count = 0
            for header_file_contents_string in header_file_contents:
                include_guard_lst = re.findall(
                    regex_pattern, header_file_contents_string)

                count += len(include_guard_lst)
            if count == 3:
                break

        if count != 3:
            header_id = header_ids[0]
            print(f'{header_file} seems to be missing the expected '
                  'include guard to prevent the double inclusion problem:')
            print(f'  #ifndef {header_id}')
            print(f'  #define {header_id}')
            print('  ...')
            print(f'  #endif // {header_id}\n')
            exit_code = 1

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
