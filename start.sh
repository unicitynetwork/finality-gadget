#!/bin/bash
# helper script for development
# starts 3 BFT nodes and 3 finality gadget nodes
# requires existing "bft-core" sibling directory with prebuilt binary i.e. "../bft-core/build/ubft"

# kill any running processes
sh stop.sh

# compile
make clean build

# clean bft test-nodes dir
rm -rf ../bft-core/test-nodes

# clean local test-nodes dir
rm -rf test-nodes

networkId=3
partitionId=3
partitionTypeId=3
shardEpoch=0
shardEpochStart=0

# generate bootstrap parameter from key file and port
boot_node() {
  local home=$1
  local rootPort=$2
  nodeId=$(../bft-core/build/ubft node-id --home $home | tail -n1)
  echo "/ip4/127.0.0.1/tcp/$rootPort/p2p/$nodeId"
}

# generate BFT config
../bft-core/build/ubft root-node init --home "test-nodes/root1" -g
../bft-core/build/ubft root-node init --home "test-nodes/root2" -g
../bft-core/build/ubft root-node init --home "test-nodes/root3" -g

# generate trust base (trust-base.json)
../bft-core/build/ubft trust-base generate --home test-nodes --epoch 1 --epoch-start 1 --network-id 3 --node-info test-nodes/root1/node-info.json --node-info test-nodes/root2/node-info.json --node-info test-nodes/root3/node-info.json --output-file-name trust-base.json

../bft-core/build/ubft trust-base sign --home test-nodes/root1 --trust-base test-nodes/trust-base.json
../bft-core/build/ubft trust-base sign --home test-nodes/root2 --trust-base test-nodes/trust-base.json
../bft-core/build/ubft trust-base sign --home test-nodes/root3 --trust-base test-nodes/trust-base.json

# verify trust base
../bft-core/build/ubft trust-base verify --trust-base test-nodes/trust-base.json

# start BFT nodes
bootNodeId=$(../bft-core/build/ubft node-id --home test-nodes/root1 | tail -n1)
../bft-core/build/ubft root-node run --home test-nodes/root1 --address "/ip4/127.0.0.1/tcp/26662"                                                      --trust-base test-nodes/trust-base.json --rpc-server-address "localhost:25866" --log-format text --log-level debug --metrics prometheus >> test-nodes/root1/debug.log 2>&1 &
../bft-core/build/ubft root-node run --home test-nodes/root2 --address "/ip4/127.0.0.1/tcp/26663" --bootnodes=/ip4/127.0.0.1/tcp/26662/p2p/$bootNodeId --trust-base test-nodes/trust-base.json --rpc-server-address "localhost:25867" --log-format text --log-level debug --metrics prometheus >> test-nodes/root2/debug.log 2>&1 &
../bft-core/build/ubft root-node run --home test-nodes/root3 --address "/ip4/127.0.0.1/tcp/26664" --bootnodes=/ip4/127.0.0.1/tcp/26662/p2p/$bootNodeId --trust-base test-nodes/trust-base.json --rpc-server-address "localhost:25868" --log-format text --log-level debug --metrics prometheus >> test-nodes/root3/debug.log 2>&1 &

# generate shard node identity
../bft-core/build/ubft shard-node init --home test-nodes/fgp1 --generate
../bft-core/build/ubft shard-node init --home test-nodes/fgp2 --generate
../bft-core/build/ubft shard-node init --home test-nodes/fgp3 --generate

../bft-core/build/ubft shard-conf generate --home test-nodes --network-id $networkId --partition-id $partitionId --partition-type-id $partitionTypeId --epoch $shardEpoch --epoch-start $shardEpochStart --node-info test-nodes/fgp1/node-info.json --node-info test-nodes/fgp2/node-info.json --node-info test-nodes/fgp3/node-info.json --partition-params dFG=6 --t2-timeout 43200000

# upload FGP shard config to BFT nodes
echo "waiting for BFT nodes to start..."
sleep 10 # wait for BFT nodes to start (can be quite slow for some reason)
curl -X PUT -H "Content-Type: application/json" -d @./test-nodes/shard-conf-3_0.json http://localhost:25866/api/v1/configurations
curl -X PUT -H "Content-Type: application/json" -d @./test-nodes/shard-conf-3_0.json http://localhost:25867/api/v1/configurations
curl -X PUT -H "Content-Type: application/json" -d @./test-nodes/shard-conf-3_0.json http://localhost:25868/api/v1/configurations

# start FGP nodes
bootNode=$(boot_node test-nodes/root1 26662)

build/fgp run \
    --home "test-nodes/fgp1" \
    --trust-base test-nodes/trust-base.json \
    --shard-conf test-nodes/shard-conf-${partitionId}_${shardEpoch}.json \
    --address "/ip4/127.0.0.1/tcp/30666" \
    --bootnodes $bootNode \
    --log-format text \
    --log-level info \
    >> test-nodes/fgp1/debug.log 2>&1 &

build/fgp run \
    --home "test-nodes/fgp2" \
    --trust-base test-nodes/trust-base.json \
    --shard-conf test-nodes/shard-conf-${partitionId}_${shardEpoch}.json \
    --address "/ip4/127.0.0.1/tcp/30667" \
    --bootnodes $bootNode \
    --log-format text \
    --log-level info \
    >> test-nodes/fgp2/debug.log 2>&1 &

build/fgp run \
    --home "test-nodes/fgp3" \
    --trust-base test-nodes/trust-base.json \
    --shard-conf test-nodes/shard-conf-${partitionId}_${shardEpoch}.json \
    --address "/ip4/127.0.0.1/tcp/30668" \
    --bootnodes $bootNode \
    --log-format text \
    --log-level info \
    >> test-nodes/fgp3/debug.log 2>&1 &
