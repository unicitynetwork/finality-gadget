package partition

import (
	"context"
	gocrypto "crypto"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	testcertificates "github.com/unicitynetwork/finality-gadget/internal/testutils/certificates"
	testlogger "github.com/unicitynetwork/finality-gadget/internal/testutils/logger"
	testpeer "github.com/unicitynetwork/finality-gadget/internal/testutils/peer"
	testsig "github.com/unicitynetwork/finality-gadget/internal/testutils/sig"
	testtrustbase "github.com/unicitynetwork/finality-gadget/internal/testutils/trustbase"
	"github.com/unicitynetwork/finality-gadget/network/protocol/replication"
)

type MockValidatorNetwork struct {
	sentMessages []any
}

func (m *MockValidatorNetwork) Send(_ context.Context, msg any, _ ...peer.ID) error {
	m.sentMessages = append(m.sentMessages, msg)
	return nil
}

func (m *MockValidatorNetwork) ReceivedChannel() <-chan any { return nil }

func (m *MockValidatorNetwork) RegisterValidatorProtocols() error { return nil }

func (m *MockValidatorNetwork) lastResponse() *replication.LedgerReplicationResponse {
	if len(m.sentMessages) == 0 {
		return nil
	}
	return m.sentMessages[len(m.sentMessages)-1].(*replication.LedgerReplicationResponse)
}

type testNodeOpts struct {
	blockCount      int
	maxReturnBlocks uint64
	committedRound  uint64
	firstRound      uint64
	partitionID     types.PartitionID
}

func createTestNode(t *testing.T, opts testNodeOpts) (*Node, *MockValidatorNetwork) {
	t.Helper()
	log := testlogger.New(t)

	if opts.maxReturnBlocks == 0 {
		opts.maxReturnBlocks = 1000
	}
	if opts.partitionID == 0 {
		opts.partitionID = 3
	}

	signer, verifier := testsig.CreateSignerAndVerifier(t)
	peerIDs := testpeer.GeneratePeerIDs(t, 1)
	nodeInfo := testtrustbase.NewNodeInfoFromVerifier(t, peerIDs[0].String(), verifier)
	trustBase := testtrustbase.NewTrustBase(t, signer)

	shardConf := &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       3,
		PartitionID:     opts.partitionID,
		ShardID:         types.ShardID{},
		PartitionTypeID: 3,
		TypeIDLen:       8,
		UnitIDLen:       256,
		T2Timeout:       2500 * time.Millisecond,
		Epoch:           0,
		EpochStart:      1,
		Validators:      []*types.NodeInfo{nodeInfo},
	}

	blockDB := memorydb.New()
	var lastUC *types.UnicityCertificate
	if opts.blockCount > 0 {
		lastUC = createTestBlocks(t, blockDB, signer, shardConf, opts.blockCount)
	}

	shardDB := memorydb.New()
	shardConfStore, err := NewShardConfStore(shardDB, log)
	require.NoError(t, err)
	require.NoError(t, shardConfStore.Store(shardConf))

	trustBaseStore, err := trustbase.NewTrustBaseStore(memorydb.New(), log)
	require.NoError(t, err)
	require.NoError(t, trustBaseStore.Store(trustBase))

	committedRound := opts.committedRound
	if committedRound == 0 && opts.blockCount > 0 {
		committedRound = uint64(opts.blockCount)
	}

	committedUC := &types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{RoundNumber: committedRound},
	}
	if lastUC != nil && committedRound == uint64(opts.blockCount) {
		committedUC = lastUC
	}

	mockNet := &MockValidatorNetwork{}

	conf := &NodeConf{
		replicationConfig: ledgerReplicationConfig{
			maxReturnBlocks: opts.maxReturnBlocks,
			maxFetchBlocks:  1000,
			timeout:         1500 * time.Millisecond,
		},
		shardConfStore: shardConfStore,
		trustBaseStore: trustBaseStore,
	}

	fuc := &types.UnicityCertificate{
		Version:     1,
		InputRecord: &types.InputRecord{RoundNumber: opts.firstRound},
	}

	node := &Node{
		conf:              conf,
		transactionSystem: &MockTransactionSystem{committedUC: committedUC},
		blockStore:        blockDB,
		state:             &ConsensusState{status: normal, fuc: fuc},
		network:           mockNet,
		replicationCh:     make(chan replicationRequest, 1),
		log:               log,
	}
	node.shardConf.Store(shardConf)

	return node, mockNet
}

func createTestBlocks(t *testing.T, db keyvaluedb.KeyValueDB, signer abcrypto.Signer, shardConf *types.PartitionDescriptionRecord, count int) *types.UnicityCertificate {
	t.Helper()
	prevBlockHash := []byte("genesis")
	var prevStateHash []byte
	var lastUC *types.UnicityCertificate

	for i := 1; i <= count; i++ {
		h := &types.Header{
			Version:           1,
			PartitionID:       shardConf.PartitionID,
			PreviousBlockHash: prevBlockHash,
			ProposerID:        shardConf.Validators[0].NodeID,
		}
		stateHash := []byte{byte(i)}
		blockHash, err := types.BlockHash(gocrypto.SHA256, h, []*types.TransactionRecord{}, stateHash, prevStateHash)
		require.NoError(t, err)

		ir := &types.InputRecord{
			RoundNumber:  uint64(i),
			Hash:         stateHash,
			PreviousHash: prevStateHash,
			BlockHash:    blockHash,
			Epoch:        0,
			SummaryValue: []byte{},
			ETHash:       []byte{},
			Timestamp:    uint64(time.Now().UnixMilli()),
		}

		uc := testcertificates.CreateUnicityCertificate(t, signer, ir, shardConf, uint64(i), nil, make([]byte, 32))
		ucBytes, err := types.Cbor.Marshal(uc)
		require.NoError(t, err)

		b := &types.Block{
			Header:             h,
			Transactions:       make([]*types.TransactionRecord, 0),
			UnicityCertificate: ucBytes,
		}
		require.NoError(t, db.Write(util.Uint64ToBytes(uint64(i)), b))

		prevBlockHash = uc.GetBlockHash()
		prevStateHash = uc.GetStateHash()
		lastUC = uc
	}
	return lastUC
}

func newReplicationRequest(partitionID types.PartitionID, shardID types.ShardID, nodeID string, begin, end uint64) *replication.LedgerReplicationRequest {
	return &replication.LedgerReplicationRequest{
		UUID:             uuid.New(),
		PartitionID:      partitionID,
		ShardID:          shardID,
		NodeID:           nodeID,
		BeginBlockNumber: begin,
		EndBlockNumber:   end,
	}
}

func TestProcessReplicationRequest_ReturnsRequestedBlocks(t *testing.T) {
	// when node has blocks 1-5
	node, mockNet := createTestNode(t, testNodeOpts{blockCount: 5})
	peerIDs := testpeer.GeneratePeerIDs(t, 1)

	// and request asks for blocks 2-4
	req := newReplicationRequest(node.PartitionID(), node.ShardID(), peerIDs[0].String(), 2, 4)
	node.processReplicationRequest(t.Context(), req)

	// then exactly blocks 2-4 are returned
	resp := mockNet.lastResponse()
	require.NotNil(t, resp)
	require.Equal(t, replication.Ok, resp.Status)
	require.Len(t, resp.Blocks, 3)
	require.Equal(t, uint64(2), resp.FirstBlockNumber)
	require.Equal(t, uint64(4), resp.LastBlockNumber)
}

func TestProcessReplicationRequest_RespectsMaxReturnBlocks(t *testing.T) {
	// when node is configured to return 3 blocks at most
	node, mockNet := createTestNode(t, testNodeOpts{blockCount: 10, maxReturnBlocks: 3})
	peerIDs := testpeer.GeneratePeerIDs(t, 1)

	// and request asks for 10 blocks
	req := newReplicationRequest(node.PartitionID(), node.ShardID(), peerIDs[0].String(), 1, 10)
	node.processReplicationRequest(t.Context(), req)

	// then only 3 blocks are returned
	resp := mockNet.lastResponse()
	require.NotNil(t, resp)
	require.Equal(t, replication.Ok, resp.Status)
	require.Len(t, resp.Blocks, 3)
	require.Equal(t, uint64(1), resp.FirstBlockNumber)
	require.Equal(t, uint64(3), resp.LastBlockNumber)
}

func TestProcessReplicationRequest_CancelledContext(t *testing.T) {
	// when context is already cancelled
	node, mockNet := createTestNode(t, testNodeOpts{blockCount: 5})
	peerIDs := testpeer.GeneratePeerIDs(t, 1)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// and a replication request is processed
	req := newReplicationRequest(node.PartitionID(), node.ShardID(), peerIDs[0].String(), 1, 5)
	node.processReplicationRequest(ctx, req)

	// then no response is sent
	require.Empty(t, mockNet.sentMessages)
}

func TestHandleLedgerReplicationRequest_BusyWhenChannelFull(t *testing.T) {
	// when replication worker is already busy
	node, mockNet := createTestNode(t, testNodeOpts{blockCount: 5})
	peerIDs := testpeer.GeneratePeerIDs(t, 1)
	node.replicationCh <- replicationRequest{}

	// and another replication request arrives
	req := newReplicationRequest(node.PartitionID(), node.ShardID(), peerIDs[0].String(), 1, 5)
	err := node.handleLedgerReplicationRequest(t.Context(), req)
	require.NoError(t, err)

	// then the request is rejected with Busy status
	resp := mockNet.lastResponse()
	require.NotNil(t, resp)
	require.Equal(t, replication.Busy, resp.Status)
}

func TestHandleLedgerReplicationRequest_BlocksNotFound(t *testing.T) {
	// when node has blocks up to round 3
	node, mockNet := createTestNode(t, testNodeOpts{blockCount: 3, committedRound: 3})
	peerIDs := testpeer.GeneratePeerIDs(t, 1)

	// and request asks for blocks starting at round 5
	req := newReplicationRequest(node.PartitionID(), node.ShardID(), peerIDs[0].String(), 5, 10)
	err := node.handleLedgerReplicationRequest(t.Context(), req)
	require.NoError(t, err)

	// then BlocksNotFound is returned
	resp := mockNet.lastResponse()
	require.NotNil(t, resp)
	require.Equal(t, replication.BlocksNotFound, resp.Status)
}

func TestHandleLedgerReplicationRequest_WrongShard(t *testing.T) {
	// when node belongs to partition 3
	node, mockNet := createTestNode(t, testNodeOpts{blockCount: 3, partitionID: 3})
	peerIDs := testpeer.GeneratePeerIDs(t, 1)

	// and request is for partition 99
	req := newReplicationRequest(99, node.ShardID(), peerIDs[0].String(), 1, 3)
	err := node.handleLedgerReplicationRequest(t.Context(), req)
	require.NoError(t, err)

	// then WrongShard is returned
	resp := mockNet.lastResponse()
	require.NotNil(t, resp)
	require.Equal(t, replication.WrongShard, resp.Status)
}
