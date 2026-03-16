#!/bin/bash
# helper script for development
# restarts 3 FGP nodes

# kill any running nodes
pkill -x fgp

boot_node() {
  local home=$1
  local rootPort=$2
  nodeId=$(../bft-core/build/ubft node-id --home $home | tail -n1)
  echo "/ip4/127.0.0.1/tcp/$rootPort/p2p/$nodeId"
}
bootNode=$(boot_node test-nodes/root1 26662)

# start FGP nodes
build/fgp run \
    --home "test-nodes/fgp1" \
    --trust-base test-nodes/trust-base.json \
    --shard-conf test-nodes/shard-conf-3_0.json \
    --address "/ip4/127.0.0.1/tcp/30666" \
    --bootnodes $bootNode \
    --log-format text \
    --log-level info \
    >> test-nodes/fgp1/debug.log 2>&1 &

build/fgp run \
    --home "test-nodes/fgp2" \
    --trust-base test-nodes/trust-base.json \
    --shard-conf test-nodes/shard-conf-3_0.json \
    --address "/ip4/127.0.0.1/tcp/30667" \
    --bootnodes $bootNode \
    --log-format text \
    --log-level info \
    >> test-nodes/fgp2/debug.log 2>&1 &

build/fgp run \
    --home "test-nodes/fgp3" \
    --trust-base test-nodes/trust-base.json \
    --shard-conf test-nodes/shard-conf-3_0.json \
    --address "/ip4/127.0.0.1/tcp/30668" \
    --bootnodes $bootNode \
    --log-format text \
    --log-level info \
    >> test-nodes/fgp3/debug.log 2>&1 &
