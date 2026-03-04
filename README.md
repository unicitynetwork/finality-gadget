# Finality Gadget (FGP)

Finality Gadget implementation for the Unicity Network as defined in the Unicity Yellowpaper. 
https://github.com/unicitynetwork/unicity-yellowpaper-tex

The FGP is a partition under Unicity BFT. The partition has type id 3 and also instance id of 3.
It is a headers-only partition (with no units or transactions, and no state or block data other 
than the hash of the PoW block being finalized).

See Sec 6.3 Finality Gadget of the YP for more details.

## Prerequisites

- **Go**: 1.24 or higher (Required for **local** builds and testing)
- **Make**: (Optional, for using the Makefile)
- **Docker**: (Optional, for containerized builds; handles Go internally)

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
