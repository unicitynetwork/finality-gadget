# Finality Gadget Partition (FGP)

FGP implementation for the Unicity Network as defined in the Yellowpaper. 
https://github.com/unicitynetwork/unicity-yellowpaper-tex

The FGP is a partition under Unicity BFT. 
It is a headers-only partition (with no units or transactions, and no state or block data other 
than the hash of the PoW block being finalized).

The finality gadget operates by periodically querying the underlying Proof-of-Work (PoW) `unicity-node` to fetch the
current best block header. By default, every 2.4 hours, the FGP leader proposes a new state transition that includes the
hash of this PoW block. Once certified by the BFT partition via a Unicity Certificate (UC), this PoW block is considered
finalized and added to the partition state, preventing deep reorgs on the base layer.

See Sec 6.3 Finality Gadget of the YP for more details.

## Prerequisites

- **Go**: 1.24 or higher
- **Make**: (Optional, for using the Makefile)
- **Docker**: (Optional)

## Building the Project

The easiest way to build the project is using the provided `Makefile`.

### Local Build

To build the `fgp` binary locally:

```bash
make build
```

This will create the executable in the `build/` directory: `./build/fgp`.

### Docker Build

To build a containerized version of the application:

```bash
make build-docker
```

This creates a Docker image tagged as `unicity-fgp:local`.

## Testing

To run all tests in the project recursively:

```bash
make test
```

## Cleaning Up

To remove the `build/` directory and any generated binaries:

```bash
make clean
```

## Usage

Once built, you can run the node using the CLI. For a list of available commands and flags:

```bash
./build/fgp --help
```

Or via Docker:

```bash
docker run unicity-fgp:local --help
```

### Example Run Command

The following is an example of how to start an FGP node locally. By default, the node assumes the underlying PoW socket
is located at `$HOME/.unicity/node.sock` (configurable via `--pow-socket-path`).

```bash
build/fgp run \
    --home "test-nodes/fgp1" \
    --trust-base test-nodes/trust-base.json \
    --shard-conf test-nodes/shard-conf-3_0.json \
    --address "/ip4/127.0.0.1/tcp/30666" \
    --bootnodes "/ip4/127.0.0.1/tcp/26662/p2p/16Uiu2HAmQMpRWSCskWgsHnAPqHCcUHqe9hHS3Sxta3ziAsz7yU1h" \
    --log-format text \
    --log-level info
```
