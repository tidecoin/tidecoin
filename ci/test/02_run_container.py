#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

import os
import shlex
import subprocess
import sys
import tempfile


def run(cmd, **kwargs):
    print("+ " + shlex.join(cmd), flush=True)
    try:
        return subprocess.run(cmd, check=True, **kwargs)
    except Exception as e:
        sys.exit(e)


def main():
    print("Export only allowed settings:")
    settings = run(
        ["bash", "-c", "grep export ./ci/test/00_setup_env*.sh"],
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf8",
    ).stdout.splitlines()
    settings = set(l.split("=")[0].split("export ")[1] for l in settings)
    # Add "hidden" settings, which are never exported, manually. Otherwise,
    # they will not be passed on.
    settings.update([
        "BASE_BUILD_DIR",
        "CI_FAILFAST_TEST_LEAVE_DANGLING",
    ])

    # Concurrent invocations of the same configuration must not overwrite one
    # another's paths/settings before docker run reads its environment file.
    with tempfile.NamedTemporaryFile(mode="w", prefix="tidecoin-ci-env-", encoding="utf8") as file:
        os.environ["CI_ENV_FILE"] = file.name
        for k, v in os.environ.items():
            if k in settings:
                file.write(f"{k}={v}\n")
        file.flush()
        run(["cat", file.name])
        run(["./ci/test/02_run_container.sh"])  # run the remainder



if __name__ == "__main__":
    main()
