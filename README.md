
# PEPC-Boost Relay

A prototype for an out-of-protocol PEPC-type block allocation mechanism (PBS).

Currently in works! Please use it with caution!

### See also
* [pepc-boost-docs](https://github.com/bharath-123/pepc-boost-docs)

### Components

The relay consists of three main components, which are designed to run and scale independently and to be as simple as possible:

1. [API](https://github.com/flashbots/mev-boost-relay/tree/main/services/api): Services that provide APIs for (a) proposers, (b) block builders, (c) data.
1. [Website](https://github.com/flashbots/mev-boost-relay/tree/main/services/website): Serving the [website requests](https://boost-relay.flashbots.net/) (information is pulled from Redis and database).
1. [Housekeeper](https://github.com/flashbots/mev-boost-relay/tree/main/services/housekeeper): Updates known validators, proposer duties, and more in the background. Only a single instance of this should run.

### Dependencies

1. Redis
1. PostgreSQL
1. one or more beacon nodes
1. block submission validation nodes
1. [optional] Memcached

### Beacon nodes / CL clients

- The relay services need access to one or more beacon node for event subscriptions (in particular the `head` and `payload_attributes` topics).
- You can specify multiple beacon nodes by providing a comma separated list of beacon node URIs.
- The beacon nodes need to support the [`payload_attributes` SSE event](https://github.com/ethereum/beacon-APIs/pull/305).
- Support the [v2 CL publish block endpoint](https://github.com/ethereum/beacon-APIs/pull/317) in the current main branch, since August 2. This is still
  experimental and may or may not fully work. It requires at least one of these CL clients
  - **Lighthouse+** [v4.3.0](https://github.com/sigp/lighthouse/releases) or later. Here's a [quick guide](https://gist.github.com/metachris/bcae9ae42e2fc834804241f991351c4e) for setting up Lighthouse.
  - **Prysm** [v4.0.6](https://github.com/prysmaticlabs/prysm/releases) or later.
- The latest release (v0.26) still uses the old V1 broadcast endpoint using CL clients with custom validate-before-broadcast patches (see [README of the release for more details](https://github.com/flashbots/mev-boost-relay/tree/v0.26#beacon-nodes--cl-clients))

**Relays are strongly advised to run multiple beacon nodes!**
* The reason is that on getPayload, the block has to be validated and broadcast by a local beacon node before it is returned to the proposer.
* If the local beacon nodes don't accept it (i.e. because it's down), the block won't be returned to the proposer, which leads to the proposer missing the slot.
* The relay makes the validate+broadcast request to all beacon nodes concurrently, and returns as soon as the first request is successful.
---

# Background


[PEPC](https://ethresear.ch/t/unbundling-pbs-towards-protocol-enforced-proposer-commitments-pepc/13879?u=barnabe) as proposed by Barnabe Monnot in is an intended protocol mechanism to allow proposers to enter into commitments over the blocks they build. Some examples of possible commitments are commitments to certain types of transaction ordering, parallel block building, etc.

One of the reasons [why PEPC is useful](https://efdn.notion.site/PEPC-FAQ-0787ba2f77e14efba771ff2d903d67e4?pvs=25#b5d2966c2215482eaba942f93bdfb613) is that it allows more general block allocation mechanisms in the protocol which removes certain locked outcomes which may be sub-optimal by enshrining certain fixed block allocation mechanisms in the protocol.

[PEPC-Boost](https://efdn.notion.site/PEPC-FAQ-0787ba2f77e14efba771ff2d903d67e4#2dfe02bc6dcd48878c82647676ca8d68%29) is a proposed out-of-protocol implementation of a certain PEPC-type allocation which splits a block into a top-of-block slot and rest-of-block slot. Separate auctions fill each of these slots. PEPC-Boost intends to separate [CEX-DEX arbitrages from the rest of the block](https://arxiv.org/abs/2305.19150) by unbundling the block auction into two separate lanes, which are the top-of-block slot and rest-of-block slot which increases the competitivity and decentralization in the block building ecosystem. Integrated builder-searchers like HFTS are likelier to win the PBS auctions because they can maintain private order flows and have access to centralized exchange feeds, giving them superior top-of-block capabilities which enable them to extract much more profit than non-integrated builders and win the PBS block auctions.

PEPC-Boost also opens up the proposer block space by allowing different actors to construct segments of the whole block. Searchers can engage in an auction to bid for transactions they want to include in the top-of-block for a given slot. Builders can engage in an auction to bid for transactions they wish to have in the rest-of-block for a given slot, a form of a parallel block auction.

# Usage

## Running Postgres, Redis and Memcached
```bash
# Start PostgreSQL & Redis individually:
docker run -d -p 5432:5432 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres postgres
docker run -d -p 6379:6379 redis

# [optional] Start Memcached
docker run -d -p 11211:11211 memcached

# Or with docker-compose:
docker-compose up
```

Note: docker-compose also runs an Adminer (a web frontend for Postgres) on http://localhost:8093/?username=postgres (db: `postgres`, username: `postgres`, password: `postgres`)

Now start the services:

```bash
# The housekeeper sets up the validators, and does various housekeeping
go run . housekeeper --network sepolia --db postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

# Run APIs for sepolia (using a dummy BLS secret key)
go run . api --network sepolia --secret-key 0x607a11b45a7219cc61a3d9c5fd08c7eebd602a6a19a977f8d3771d5711a550f2 --db postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

# Run Website for sepolia
go run . website --network sepolia --db postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable

# Query status
curl localhost:9062/eth/v1/builder/status

# Send test validator registrations
curl -X POST -H'Content-Encoding: gzip' localhost:9062/eth/v1/builder/validators --data-binary @testdata/valreg2.json.gz

# Delete previous registrations
redis-cli DEL boost-relay/sepolia:validators-registration boost-relay/sepolia:validators-registration-timestamp
```


## Environment variables

#### General

* `ACTIVE_VALIDATOR_HOURS` - number of hours to track active proposers in redis (default: `3`)
* `API_MAX_HEADER_BYTES` - http maximum header bytes (default: `60_000`)
* `API_TIMEOUT_READ_MS` - http read timeout in milliseconds (default: `1_500`)
* `API_TIMEOUT_READHEADER_MS` - http read header timeout in milliseconds (default: `600`)
* `API_TIMEOUT_WRITE_MS` - http write timeout in milliseconds (default: `10_000`)
* `API_TIMEOUT_IDLE_MS` - http idle timeout in milliseconds (default: `3_000`)
* `API_SHUTDOWN_WAIT_SEC` - how long to wait on shutdown before stopping server, to allow draining of requests (default: `30`)
* `API_SHUTDOWN_STOP_SENDING_BIDS` - whether API should stop sending bids during shutdown (nly useful in single-instance/testnet setups, default: `false`)
* `BLOCKSIM_MAX_CONCURRENT` - maximum number of concurrent block-sim requests (0 for no maximum, default: `4`)
* `BLOCKSIM_TIMEOUT_MS` - builder block submission validation request timeout (default: `3000`)
* `BROADCAST_MODE` - which broadcast mode to use for block publishing (default: `consensus_and_equivocation`)
* `DB_DONT_APPLY_SCHEMA` - disable applying DB schema on startup (useful for connecting data API to read-only replica)
* `DB_TABLE_PREFIX` - prefix to use for db tables (default uses `dev`)
* `GETPAYLOAD_RETRY_TIMEOUT_MS` - getPayload retry getting a payload if first try failed (default: `100`)
* `MEMCACHED_URIS` - optional comma separated list of memcached endpoints, typically used as secondary storage alongside Redis
* `MEMCACHED_EXPIRY_SECONDS` - item expiry timeout when using memcache (default: `45`)
* `MEMCACHED_CLIENT_TIMEOUT_MS` - client timeout in milliseconds (default: `250`)
* `MEMCACHED_MAX_IDLE_CONNS` - client max idle conns (default: `10`)
* `NUM_ACTIVE_VALIDATOR_PROCESSORS` - proposer API - number of goroutines to listen to the active validators channel
* `NUM_VALIDATOR_REG_PROCESSORS` - proposer API - number of goroutines to listen to the validator registration channel
* `NO_HEADER_USERAGENTS` - proposer API - comma separated list of user agents for which no bids should be returned
* `ENABLE_BUILDER_CANCELLATIONS` - whether to enable block builder cancellations
* `REDIS_URI` - main redis URI (default: `localhost:6379`)
* `REDIS_READONLY_URI` - optional, a secondary redis instance for heavy read operations

#### Feature Flags

* `DISABLE_PAYLOAD_DATABASE_STORAGE` - builder API - disable storing execution payloads in the database (i.e. when using memcached as data availability redundancy)
* `DISABLE_LOWPRIO_BUILDERS` - reject block submissions by low-prio builders
* `FORCE_GET_HEADER_204` - force 204 as getHeader response
* `ENABLE_IGNORABLE_VALIDATION_ERRORS` - enable ignorable validation errors

#### Development Environment Variables

* `RUN_DB_TESTS` - when set to "1" enables integration tests with Postgres using endpoint specified by environment variable `TEST_DB_DSN`
* `RUN_INTEGRATION_TESTS` - when set to "1" enables integration tests, currently used for testing Memcached using comma separated list of endpoints specified by `MEMCACHED_URIS`
* `TEST_DB_DSN` - specifies connection string using Data Source Name (DSN) for Postgres (default: postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable)

#### Redis tuning

* `REDIS_CONNECTION_POOL_SIZE`, `REDIS_MIN_IDLE_CONNECTIONS`, `REDIS_READ_TIMEOUT_SEC`, `REDIS_POOL_TIMEOUT_SEC`, `REDIS_WRITE_TIMEOUT_SEC` (see also [the code here](https://github.com/flashbots/mev-boost-relay/blob/e39cd38010de26bf9a51d1a3e77fc235ea87b12f/datastore/redis.go#L35-L41))

## Updating the website

* Edit the HTML in `services/website/website.html`
* Edit template values in `testdata/website-htmldata.json`
* Generate a static version of the website with `go run scripts/website-staticgen/main.go`

This builds a local copy of the template and saves it in `website-index.html`

The website is using:
* [PureCSS](https://purecss.io/)
* [HeroIcons](https://heroicons.com/)

---

# Technical Notes

See [ARCHITECTURE.md](ARCHITECTURE.md) and [Running MEV-Boost-Relay at scale](https://flashbots.notion.site/Draft-Running-a-relay-4040ccd5186c425d9a860cbb29bbfe09) for more technical details!

## Storing execution payloads and redundant data availability

By default, the execution payloads for all block submission are stored in Redis and also in the Postgres database,
to provide redundant data availability for getPayload responses. But the database table is not pruned automatically,
because it takes a lot of resources to rebuild the indexes (and a better option is using `TRUNCATE`).

Storing all the payloads in the database can lead to terabytes of data in this particular table. Now it's also possible
to use memcached as a second data availability layer. Using memcached is optional and disabled by default.

To enable memcached, you just need to supply the memcached URIs either via environment variable (i.e.
`MEMCACHED_URIS=localhost:11211`) or through command line flag (`--memcached-uris`).

You can disable storing the execution payloads in the database with this environment variable:
`DISABLE_PAYLOAD_DATABASE_STORAGE=1`.

## Builder nodes RPC

You can use the [pepc-boost-builder project](https://github.com/bharath-123/pepc-boost-builder) to validate tob tx submissions, block builder submissions and to assemble tob and rob txs: https://github.com/bharath-123/pepc-boost-builder

Here's an example systemd config:

<details>
<summary><code>/etc/systemd/system/geth.service</code></summary>

```ini
[Unit]
Description=mev-boost
Wants=network-online.target
After=network-online.target

[Service]
User=ubuntu
Group=ubuntu
Environment=HOME=/home/ubuntu
Type=simple
KillMode=mixed
KillSignal=SIGINT
TimeoutStopSec=90
Restart=on-failure
RestartSec=10s
ExecStart=/home/ubuntu/builder/build/bin/geth \
    --syncmode=snap \
    --datadir /var/lib/goethereum \
    --metrics \
    --metrics.expensive \
    --http \
    --http.api="engine,eth,web3,net,debug,flashbots" \
    --http.corsdomain "*" \
    --http.addr "0.0.0.0" \
    --http.port 8545 \
    --http.vhosts '*' \
    --ws \
    --ws.api="engine,eth,web3,net,debug" \
    --ws.addr 0.0.0.0 \
    --ws.port 8546 \
    --ws.api engine,eth,net,web3 \
    --ws.origins '*' \
    --graphql \
    --graphql.corsdomain '*' \
    --graphql.vhosts '*' \
    --authrpc.addr="0.0.0.0" \
    --authrpc.jwtsecret=/var/lib/goethereum/jwtsecret \
    --authrpc.vhosts '*' \
    --cache=8192

[Install]
WantedBy=multi-user.target
```
</details>

Sending blocks to the validation node:

- The built-in [blocksim-ratelimiter](services/api/blocksim_ratelimiter.go) is a simple example queue implementation.
- By default, `BLOCKSIM_MAX_CONCURRENT` is set to 4, which allows 4 concurrent block simulations per API node
- For production use, use the [prio-load-balancer](https://github.com/flashbots/prio-load-balancer) project for a single priority queue,
  and disable the internal concurrency limit (set `BLOCKSIM_MAX_CONCURRENT` to `0`).

## Beacon node setup

### Lighthouse

- Lighthouse with validation and equivocaation check before broadcast: https://github.com/sigp/lighthouse/pull/4168
- with `--always-prepare-payload` and `--prepare-payload-lookahead 12000` flags, and some junk feeRecipeint

Here's a [quick guide](https://gist.github.com/metachris/bcae9ae42e2fc834804241f991351c4e) for setting up Lighthouse.

Here's an example Lighthouse systemd config:

<details>
<summary><code>/etc/systemd/system/lighthouse.service</code></summary>

```ini
[Unit]
Description=Lighthouse
After=network.target
Wants=network.target

[Service]
User=ubuntu
Group=ubuntu
Type=simple
Restart=always
RestartSec=5
TimeoutStopSec=180
ExecStart=/home/ubuntu/.cargo/bin/lighthouse bn \
        --network mainnet \
        --checkpoint-sync-url=https://mainnet-checkpoint-sync.attestant.io \
        --eth1 \
        --http \
        --http-address "0.0.0.0" \
        --http-port 3500 \
        --datadir=/mnt/data/lighthouse \
        --http-allow-sync-stalled \
        --execution-endpoints=http://localhost:8551 \
        --jwt-secrets=/var/lib/goethereum/jwtsecret \
        --disable-deposit-contract-sync \
        --always-prepare-payload \
        --prepare-payload-lookahead 12000

[Install]
WantedBy=default.target
```

</details>


### Prysm

- Prysm with validation and equivocaation check before broadcast: https://github.com/prysmaticlabs/prysm/pull/12335
- use `--grpc-max-msg-size 104857600`, because by default the getAllValidators response is too big and fails

Here's an example Prysm systemd config:

<details>
<summary><code>/etc/systemd/system/prysm.service</code></summary>

```ini
[Unit]
Description=Prysm
After=network.target
Wants=network.target

[Service]
User=ubuntu
Group=ubuntu
Type=simple
Restart=always
RestartSec=5
TimeoutStopSec=180
ExecStart=/home/ubuntu/prysm/bazel-bin/cmd/beacon-chain/beacon-chain_/beacon-chain \
        --accept-terms-of-use \
        --enable-debug-rpc-endpoints \
        --checkpoint-sync-url=https://mainnet-checkpoint-sync.attestant.io \
        --genesis-beacon-api-url=https://mainnet-checkpoint-sync.attestant.io \
        --grpc-gateway-host "0.0.0.0" \
        --datadir=/mnt/data/prysm \
        --p2p-max-peers 100 \
        --execution-endpoint=http://localhost:8551 \
        --jwt-secret=/var/lib/goethereum/jwtsecret \
        --min-sync-peers=1 \
        --grpc-max-msg-size 104857600 \
        --prepare-all-payloads \
        --disable-reorg-late-blocks

[Install]
WantedBy=default.target
```

</details>

## Bid Cancellations

Cancellations are not yet supported in PEPC-Boost

