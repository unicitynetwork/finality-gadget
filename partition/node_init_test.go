package partition

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	testcertificates "github.com/unicitynetwork/finality-gadget/internal/testutils/certificates"
	testlogger "github.com/unicitynetwork/finality-gadget/internal/testutils/logger"
	testsig "github.com/unicitynetwork/finality-gadget/internal/testutils/sig"
	testtrustbase "github.com/unicitynetwork/finality-gadget/internal/testutils/trustbase"
	"github.com/unicitynetwork/finality-gadget/txsystem/state"
)

type MockTransactionSystem struct {
	committedUC  *types.UnicityCertificate
	currentState []byte
}

func (m *MockTransactionSystem) StateSummary() (*state.Summary, error) {
	return state.NewStateSummary(m.currentState, []byte{}, 0, nil), nil
}

func (m *MockTransactionSystem) LeaderPropose(ctx context.Context, round uint64) (*state.Summary, error) {
	return nil, nil
}

func (m *MockTransactionSystem) FollowerVerify(ctx context.Context, round uint64, proposedRoot []byte) (*state.Summary, error) {
	return state.NewStateSummary(proposedRoot, []byte{}, 0, nil), nil
}

func (m *MockTransactionSystem) UpdateConfig(shardConf *types.PartitionDescriptionRecord) error {
	return nil
}

func (m *MockTransactionSystem) RestoreState(ctx context.Context, uc *types.UnicityCertificate) error {
	m.committedUC = uc
	m.currentState = uc.GetStateHash()
	return nil
}

func (m *MockTransactionSystem) Revert() {}

func (m *MockTransactionSystem) Commit(uc *types.UnicityCertificate) error {
	m.committedUC = uc
	m.currentState = uc.GetStateHash()
	return nil
}

func (m *MockTransactionSystem) CommittedUC() *types.UnicityCertificate {
	if m.committedUC == nil {
		return &types.UnicityCertificate{
			Version:     1,
			InputRecord: &types.InputRecord{RoundNumber: 0},
		}
	}
	return m.committedUC
}

func TestNodeStartupAndRecoveryEquivalence(t *testing.T) {
	log := testlogger.New(t)

	keyConf, nodeInfo := createKeyConf(t)
	shardConf := &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       3,
		PartitionID:     3,
		ShardID:         types.ShardID{},
		PartitionTypeID: 3,
		TypeIDLen:       8,
		UnitIDLen:       256,
		T2Timeout:       2500 * time.Millisecond,
		Epoch:           0,
		EpochStart:      1,
		Validators:      []*types.NodeInfo{nodeInfo},
	}
	signer, _ := testsig.CreateSignerAndVerifier(t)
	trustBase := testtrustbase.NewTrustBase(t, signer)

	shardDB := memorydb.New()
	shardConfStore, err := NewShardConfStore(shardDB, log)
	require.NoError(t, err)
	require.NoError(t, shardConfStore.Store(shardConf))

	trustBaseStore, err := trustbase.NewTrustBaseStore(memorydb.New(), log)
	require.NoError(t, err)
	require.NoError(t, trustBaseStore.Store(trustBase))

	// Create 3 historical blocks
	var blocks []*types.Block
	prevBlockHash := []byte("genesis")
	prevStateHash := []byte(nil)
	for i := 1; i <= 3; i++ {
		h := &types.Header{
			Version:           1,
			PartitionID:       3,
			PreviousBlockHash: prevBlockHash,
			ProposerID:        nodeInfo.NodeID,
		}
		txs := make([]*types.TransactionRecord, 0)
		stateHash := []byte{byte(i)}

		blockHash, err := types.BlockHash(crypto.SHA256, h, []*types.TransactionRecord{}, stateHash, prevStateHash)
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
			Transactions:       txs,
			UnicityCertificate: ucBytes,
		}
		blocks = append(blocks, b)

		prevBlockHash = uc.GetBlockHash()
		prevStateHash = uc.GetStateHash()
	}

	// 1. Simulate Startup Initialization (Fast-forward via blockStore.Last)
	blockDBInit := memorydb.New()
	for i, b := range blocks {
		err := blockDBInit.Write(util.Uint64ToBytes(uint64(i+1)), b)
		require.NoError(t, err)
	}

	confInit, err := NewNodeConf(keyConf, shardConfStore, trustBaseStore,
		WithBlockDB(blockDBInit),
		WithUnicityCertificateValidator(&AlwaysValidCertificateValidator{}),
	)
	require.NoError(t, err)

	txSystemInit := &MockTransactionSystem{currentState: []byte("genesis")}
	nodeInit := &Node{
		conf:              confInit,
		transactionSystem: txSystemInit,
		blockStore:        confInit.blockDB,
		state:             &ConsensusState{status: initializing},
		shardConfStore:    confInit.shardConfStore,
		trustBaseStore:    confInit.trustBaseStore,
		log:               log,
	}
	err = nodeInit.initState(context.Background())
	require.NoError(t, err)

	require.Equal(t, uint64(3), txSystemInit.CommittedUC().GetRoundNumber())
	require.Equal(t, []byte{3}, txSystemInit.currentState)

	// 2. Simulate Network Recovery (Empty DB initially, catch up via handleBlock)
	blockDBRec := memorydb.New()
	confRec, err := NewNodeConf(keyConf, shardConfStore, trustBaseStore,
		WithBlockDB(blockDBRec),
		WithUnicityCertificateValidator(&AlwaysValidCertificateValidator{}),
	)
	require.NoError(t, err)

	// Initial UC (round 0)
	initialUC := &types.UnicityCertificate{
		Version: 1,
		InputRecord: &types.InputRecord{
			RoundNumber: 0,
			BlockHash:   []byte("genesis"),
		},
	}
	txSystemRec := &MockTransactionSystem{
		currentState: []byte(nil),
		committedUC:  initialUC,
	}

	nodeRec := &Node{
		conf:              confRec,
		transactionSystem: txSystemRec,
		blockStore:        confRec.blockDB,
		state:             &ConsensusState{status: recovering},
		shardConfStore:    confRec.shardConfStore,
		trustBaseStore:    confRec.trustBaseStore,
		log:               log,
	}
	nodeRec.state.fuc = initialUC
	nodeRec.state.luc = initialUC
	nodeRec.shardConf.Store(shardConf)

	// Apply blocks sequentially
	for _, b := range blocks {
		err := nodeRec.handleBlock(context.Background(), b)
		require.NoError(t, err)
	}

	require.Equal(t, uint64(3), txSystemRec.CommittedUC().GetRoundNumber())
	require.Equal(t, []byte{3}, txSystemRec.currentState)

	// Compare that the end states of transaction systems are identical
	require.Equal(t, txSystemInit.CommittedUC().GetRoundNumber(), txSystemRec.CommittedUC().GetRoundNumber())
	require.Equal(t, txSystemInit.currentState, txSystemRec.currentState)
}
