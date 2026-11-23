# Fuzzing Tidecoin using libFuzzer

## Quickstart guide

To quickly get started fuzzing Tidecoin using [libFuzzer](https://llvm.org/docs/LibFuzzer.html):

```sh
$ git clone https://github.com/tidecoin/tidecoin
$ cd tidecoin/
$ cmake --preset=libfuzzer
# macOS users: If you have problem with this step then make sure to read "macOS hints for
# libFuzzer" on https://github.com/tidecoin/tidecoin/blob/master/doc/fuzzing.md#macos-hints-for-libfuzzer
$ cmake --build build_fuzz
$ FUZZ=process_message build_fuzz/bin/fuzz
# abort fuzzing using ctrl-c
```

To run without common sanitizers, use the `libfuzzer-nosan` preset. This preset
uses a separate `build_fuzz_nosan` build directory:

```sh
$ cmake --preset=libfuzzer-nosan
$ cmake --build build_fuzz_nosan
$ FUZZ=process_message build_fuzz_nosan/bin/fuzz
```

See [further](#run-without-sanitizers-for-increased-throughput) for more information.

There is also a runner script to execute all fuzz targets. Refer to
`./build_fuzz/test/fuzz/test_runner.py --help` for more details.

## Overview of Tidecoin fuzzing

[Google](https://github.com/google/fuzzing/) has a good overview of fuzzing in general, with contributions from key architects of some of the most-used fuzzers. [John Regehr](https://blog.regehr.org/archives/1687) provides good advice on writing code that assists fuzzers in finding bugs, which is useful for developers to keep in mind.

## Fuzzing harnesses and output

[`process_message`](https://github.com/tidecoin/tidecoin/blob/master/src/test/fuzz/process_message.cpp) is a fuzzing harness for the [`ProcessMessage(...)` function (`net_processing`)](https://github.com/tidecoin/tidecoin/blob/master/src/net_processing.cpp). The available fuzzing harnesses are found in [`src/test/fuzz/`](https://github.com/tidecoin/tidecoin/tree/master/src/test/fuzz).

The fuzzer will output `NEW` every time it has created a test input that covers new areas of the code under test. For more information on how to interpret the fuzzer output, see the [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html).

## Using the MemorySanitizer (MSan)

MSan [requires](https://clang.llvm.org/docs/MemorySanitizer.html#handling-external-code)
that all linked code be instrumented. The exact steps to achieve this may vary
but involve compiling `clang` from source, using the built `clang` to compile
an instrumentalized libc++, then using it to build [Tidecoin dependencies
from source](../depends/README.md) and finally the Tidecoin fuzz binary
itself. One can use the MSan CI job as an example for how to perform these
steps.

Valgrind is an alternative to MSan that does not require building a custom libc++.

## Run without sanitizers for increased throughput

Fuzzing on a harness compiled with `-DSANITIZERS=address,fuzzer,undefined` is
good for finding bugs. However, the very slow execution even under libFuzzer
will limit the ability to find new coverage. A good approach is to perform
occasional long runs without the additional bug-detectors
(`--preset=libfuzzer-nosan`) and then merge new inputs into a corpus.
Patience is useful; even with improved throughput, libFuzzer may need days and
10s of millions of executions to reach deep/hard targets.

## Building and debugging fuzz tests

There are 3 ways fuzz tests can be built:

1. With `-DBUILD_FOR_FUZZING=ON` which forces on fuzz determinism (skipping
   proof of work checks, disabling random number seeding, disabling clock time)
   and causes `Assume()` checks to abort on failure.

   This is the normal way to run fuzz tests and generate new inputs. Because
   determinism is hardcoded on in this build, only the fuzz binary can be built
   and all other binaries are disabled.

2. With `-DBUILD_FUZZ_BINARY=ON -DCMAKE_BUILD_TYPE=Debug` which causes
   `Assume()` checks to abort on failure, and enables fuzz determinism, but
   makes it optional.

   Determinism is turned on in the fuzz binary by default, but can be turned off
   by setting the `FUZZ_NONDETERMINISM` environment variable to any value, which
   may be useful for running fuzz tests with code that deterministic execution
   would otherwise skip.

   Since `BUILD_FUZZ_BINARY`, unlike `BUILD_FOR_FUZZING`, does not hardcode on
   determinism, this allows non-fuzz binaries to coexist in the same build,
   making it possible to reproduce fuzz test failures in a normal build.

3. With `-DBUILD_FUZZ_BINARY=ON -DCMAKE_BUILD_TYPE=Release`. In this build, the
   fuzz binary will build but refuse to run, because in release builds
   determinism is forced off and `Assume()` checks do not abort, so running the
   tests would not be useful. This build is only useful for ensuring fuzz tests
   compile and link.

## macOS hints for libFuzzer

The default Clang/LLVM version supplied by Apple on macOS does not include
fuzzing libraries, so macOS users will need to install a full version, for
example using `brew install llvm`.

You may also need to take care of giving the correct path for `clang` and
`clang++`, like `CC=/path/to/clang CXX=/path/to/clang++` if the non-systems
`clang` does not come first in your path.

Using `lld` is required due to issues with Apple's `ld` and `LLVM`.

Full configuration step for macOS:

```sh
$ brew install llvm lld
$ cmake --preset=libfuzzer \
   -DCMAKE_C_COMPILER="$(brew --prefix llvm)/bin/clang" \
   -DCMAKE_CXX_COMPILER="$(brew --prefix llvm)/bin/clang++" \
   -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld"
```

Read the [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html) for more information. This [libFuzzer tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md) might also be of interest.

# Fuzzing Tidecoin using afl++

## Quickstart guide

To quickly get started fuzzing Tidecoin using [afl++](https://github.com/AFLplusplus/AFLplusplus):

```sh
$ git clone https://github.com/tidecoin/tidecoin
$ cd tidecoin/
$ git clone https://github.com/AFLplusplus/AFLplusplus
$ make -C AFLplusplus/ source-only
# If afl-clang-lto is not available, see
# https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#a-selecting-the-best-afl-compiler-for-instrumenting-the-target
$ cmake -B build_fuzz \
   -DCMAKE_C_COMPILER="$(pwd)/AFLplusplus/afl-clang-lto" \
   -DCMAKE_CXX_COMPILER="$(pwd)/AFLplusplus/afl-clang-lto++" \
   -DBUILD_FOR_FUZZING=ON
$ cmake --build build_fuzz
# For macOS you may need to ignore x86 compilation checks when running "cmake --build". If so,
# try compiling using: AFL_NO_X86=1 cmake --build build_fuzz
# Also, it might be required to run "afl-system-config" to adjust the shared
# memory parameters.
$ mkdir -p inputs/ outputs/
$ echo A > inputs/thin-air-input
$ FUZZ=bech32 ./AFLplusplus/afl-fuzz -i inputs/ -o outputs/ -- build_fuzz/bin/fuzz
# You may have to change a few kernel parameters to test optimally - afl-fuzz
# will print an error and suggestion if so.
```

Read the [afl++ documentation](https://github.com/AFLplusplus/AFLplusplus) for more information.

# Fuzzing Tidecoin using Honggfuzz

## Quickstart guide

To quickly get started fuzzing Tidecoin using [Honggfuzz](https://github.com/google/honggfuzz):

```sh
$ git clone https://github.com/tidecoin/tidecoin
$ cd tidecoin/
$ git clone https://github.com/google/honggfuzz
$ cd honggfuzz/
$ make
$ cd ..
$ cmake -B build_fuzz \
   -DCMAKE_C_COMPILER="$(pwd)/honggfuzz/hfuzz_cc/hfuzz-clang" \
   -DCMAKE_CXX_COMPILER="$(pwd)/honggfuzz/hfuzz_cc/hfuzz-clang++" \
   -DBUILD_FOR_FUZZING=ON \
   -DSANITIZERS=address,undefined
$ cmake --build build_fuzz
$ mkdir -p inputs/
$ FUZZ=process_message ./honggfuzz/honggfuzz -i inputs/ -- build_fuzz/bin/fuzz
```

Read the [Honggfuzz documentation](https://github.com/google/honggfuzz/blob/master/docs/USAGE.md) for more information.

# OSS-Fuzz

If you discover a potential Tidecoin vulnerability while fuzzing, report it
privately according to the [Tidecoin security policy](../SECURITY.md). Do not
open a public issue for security bugs.

For general OSS-Fuzz disclosure practices, see Google's
[bug disclosure guidelines](https://google.github.io/oss-fuzz/getting-started/bug-disclosure-guidelines/).
