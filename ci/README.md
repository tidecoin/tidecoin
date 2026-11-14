# CI Scripts

This directory contains scripts for each build step in each build stage.

## Running a Stage Locally

Be aware that the tests will be built and run in-place, so please run at your own risk.
If the repository is not a fresh git clone, you might have to clean files from previous builds or test runs first.

The ci needs to perform various sysadmin tasks such as installing packages or writing to the user's home directory.
While it should be fine to run
the ci system locally on your development box, the ci scripts can generally be assumed to have received less review and
testing compared to other parts of the codebase. If you want to keep the work tree clean, you might want to run the ci
system in a virtual machine with a Linux operating system of your choice.

To allow for a wide range of tested environments, but also ensure reproducibility to some extent, the test stage
requires `bash`, `docker`, and `python3` to be installed. To run on different architectures than the host `qemu` is also required. To install all requirements on Ubuntu, run

```
sudo apt install bash docker.io python3 qemu-user-static
```

It is recommended to run the ci system in a clean env. To run the test stage
with a specific configuration,

```
env -i HOME="$HOME" PATH="$PATH" USER="$USER" bash -c 'FILE_ENV="./ci/test/00_setup_env_arm.sh" ./ci/test_run_all.sh'
```

## Configurations

The test files (`FILE_ENV`) are constructed to test a wide range of
configurations, rather than a single pass/fail. This helps to catch build
failures and logic errors that present on platforms other than the ones the
author has tested.

Some builders use the dependency-generator in `./depends`, rather than using
the system package manager to install build dependencies. This guarantees that
the tester is using the same versions as the release builds, which also use
`./depends`.

It is also possible to force a specific configuration without modifying the
file. For example,

```
env -i HOME="$HOME" PATH="$PATH" USER="$USER" bash -c 'MAKEJOBS="-j1" FILE_ENV="./ci/test/00_setup_env_arm.sh" ./ci/test_run_all.sh'
```

The files starting with `0n` (`n` greater than 0) are the scripts that are run
in order.

## Cache

In order to avoid rebuilding all dependencies for each build, the binaries are
cached and reused when possible. Changes in the dependency-generator will
trigger cache-invalidation and rebuilds as necessary.

## Configuring a repository for CI

### Automatic Docker cleanup on shared hosts

Each build and lint job uses an image tag and container names unique to its
configuration, workflow run, attempt and a random invocation suffix. Local runs
also receive unique names. `CONTAINER_NAME` stays stable for the persistent
ccache, depends and sources volumes; cleanup never removes those volumes.

The shell exit trap removes the job's containers and then its exact image tag
with `docker image rm --no-prune`, without forcing image deletion. An `always()`
workflow step retries this cleanup after failure or normal cancellation. Other
jobs' tags and containers are left alone, including when images share layers or
have identical contents. Buildx's existing post-job cleanup removes its own
builder and temporary build state.

Do not run global image pruning from individual jobs. With the containerd image
store, it can delete leases protecting another job's active image import, even
with an image-label filter (Moby issue
[53321](https://github.com/moby/moby/issues/53321)). Targeted tag removal does not
perform that lease sweep. No idle-host window or manual command is needed for
normal job-image cleanup.

A host crash, forcibly killed runner, or unavailable Docker daemon can prevent
cleanup and leave orphaned resources. The automatic cleanup does not remove
images left by older CI versions or manage persistent cache sizes. Any broader
host maintenance must still avoid pruning during other jobs' image operations.
`RESTART_CI_DOCKER_BEFORE_RUN` is an opt-in Podman reset for isolated environments;
do not enable it on a shared host.

### Primary repository

To configure the primary repository, follow these steps:

1. Enable GitHub Actions for the repository.
2. Permit the following actions to run:
   1. actions/cache/restore@\*
   1. actions/cache/save@\*
   1. docker/setup-buildx-action@\*
   1. actions/github-script@\*

### Forked repositories

When used in a fork the CI will run on GitHub's hosted runners. Due to
GitHub's 10GB-per-repo cache size limitation, caches may be frequently evicted
and missed, but the workflows will run.
