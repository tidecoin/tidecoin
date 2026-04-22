# Docker Testnet Deploy

The deployment workflows added for Tidecoin are isolated from the existing CI in
[.github/workflows/ci.yml](../.github/workflows/ci.yml). They only handle:

- building and pushing a Docker image
- rendering `tidecoin.conf` from a template
- deploying the rendered config and Compose file to the server

## Runtime config

The container expects `tidecoin.conf` at `/data/tidecoin.conf`.

For CI/CD deploys, the config is rendered from
[deploy/testnet/tidecoin.conf.template](../deploy/testnet/tidecoin.conf.template)
and copied to:

`/opt/runner/tidecoin/services/<service-dir>/data/tidecoin.conf`

The Compose file is rendered from
[deploy/testnet/tidecoind.compose.yml.template](../deploy/testnet/tidecoind.compose.yml.template)
and copied to the same service directory.

## Required repository secrets

- `CI_REGISTRY`
- `CI_REGISTRY_USER`
- `CI_REGISTRY_PASSWORD`
- `CI_REGISTRY_REPO`
- `GIT_ACCESS_TOKEN`

## Required `testnet` environment variables

- `SERVICE_BASE_PATH`
- `SERVICE_DIR_NAME`
- `SERVICE_NAME`
- `IMAGE_NAME`
- `DOCKER_COMPOSE_FILE`
- `TIDECOIN_CONTAINER_NAME`
- `TIDECOIN_CHAIN_FLAG`
- `TIDECOIN_CONF_NETWORK_LINE`
- `TIDECOIN_DOCKER_NETWORK`
- `TIDECOIN_HOST_DATA_DIR`
- `TIDECOIN_RPC_PORT`
- `TIDECOIN_RPC_BIND`
- `TIDECOIN_RPC_ALLOW_IP`
- `TIDECOIN_LISTEN`
- `TIDECOIN_TXINDEX`
- `TIDECOIN_DBCACHE`
- `TIDECOIN_MAX_CONNECTIONS`

The testnet deployment does not publish the node's P2P port on the host. The
service stays reachable only on the internal Docker network used by the stack.

## Required `testnet` environment secrets

- `BASIC_USER`
- `BASIC_PASS`
- `COOKIE`
- `HOST_1`
- `HOST_1_USERNAME`
- `SSH_PRIVATE_KEY`

## Manual runs

Build and optionally trigger deploy:

- `Build and release Docker image`

Deploy or rollback an already-pushed image by SHA:

- `Deploy service`
