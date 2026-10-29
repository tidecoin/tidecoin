Description
------------

This directory contains data-driven tests for various aspects of Bitcoin.

Historical Tidecoin WIF fixture
------------------------------

`falcon512_legacy_wif.json` contains public test material, never a funded key.
Its Falcon-512 key comes from `tidecoin-testkeys --scheme=7
--seed=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
--index=0 --count=1`. The three WIF strings were exported using the verbatim
`EncodeSecret` and Base58 encoder bodies from Tidecoin v0.18.3, commit
`7b525367e9ea1b614aa380a52394f0e3d3878aa9`, with an adapter supplying that
version's raw `CKey` accessors and SHA256d. This was an exporter-function test,
not an execution of the old node or a historical user backup.

The fixture pins the old format independently of the current WIF implementation:
network byte (125/180/15), 1281 raw secret bytes, `01`, 897 raw public bytes,
then the four-byte checksum. The raw public key starts with `09`; its serialized
form used in scripts starts with `07 09`. The expected P2PKH addresses hash that
serialized public key with HASH160 and use address prefixes 33/92/117. Do not
regenerate these expected WIFs through the current encoder: doing so would let
matching import/export mistakes pass unnoticed again.

License
--------

The data files in this directory are distributed under the MIT software
license, see the accompanying file COPYING or
https://www.opensource.org/licenses/mit-license.php.

