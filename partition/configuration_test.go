package partition

import (
	"crypto/rand"
	"testing"
	"time"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"

	"github.com/unicitynetwork/bft-go-base/types"

	testlogger "github.com/unicitynetwork/finality-gadget/internal/testutils/logger"
	testsig "github.com/unicitynetwork/finality-gadget/internal/testutils/sig"
	testtrustbase "github.com/unicitynetwork/finality-gadget/internal/testutils/trustbase"
	"github.com/unicitynetwork/finality-gadget/network/protocol/blockproposal"
)

type AlwaysValidCertificateValidator struct{}

func (c *AlwaysValidCertificateValidator) Validate(*types.UnicityCertificate, *types.PartitionDescriptionRecord, types.RootTrustBase) error {
	return nil
}

type AlwaysValidBlockProposalValidator struct{}

func (t *AlwaysValidBlockProposalValidator) Validate(*blockproposal.BlockProposal, *types.PartitionDescriptionRecord, types.RootTrustBase) error {
	return nil
}

func TestNewNodeConf(t *testing.T) {
	blockDB := memorydb.New()
	shardDB := memorydb.New()
	t1Timeout := 250 * time.Millisecond

	keyConf, nodeInfo := createKeyConf(t)
	shardConf := &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       5,
		PartitionID:     0x01010101,
		ShardID:         types.ShardID{},
		PartitionTypeID: 999,
		TypeIDLen:       8,
		UnitIDLen:       256,
		T2Timeout:       2500 * time.Millisecond,
		Epoch:           0,
		EpochStart:      1,
		Validators:      []*types.NodeInfo{nodeInfo},
	}
	signer, _ := testsig.CreateSignerAndVerifier(t)
	trustBase := testtrustbase.NewTrustBase(t, signer)

	log := testlogger.New(t)

	shardConfStore, err := NewShardConfStore(shardDB, log)
	require.NoError(t, err)
	require.NoError(t, shardConfStore.Store(shardConf))

	trustBaseStore, err := trustbase.NewTrustBaseStore(memorydb.New(), log)
	require.NoError(t, err)
	require.NoError(t, trustBaseStore.Store(trustBase))

	conf, err := NewNodeConf(keyConf, shardConfStore, trustBaseStore,
		WithUnicityCertificateValidator(&AlwaysValidCertificateValidator{}),
		WithBlockProposalValidator(&AlwaysValidBlockProposalValidator{}),
		WithBlockDB(blockDB),
		WithT1Timeout(t1Timeout),
		WithReplicationParams(1, 2, 1, 1000),
	)

	require.NoError(t, err)
	require.NotNil(t, conf)
	require.Equal(t, blockDB, conf.blockDB)
	require.Equal(t, shardDB, conf.shardConfStore.db)
	require.NoError(t, conf.bpValidator.Validate(nil, nil, nil))
	require.NoError(t, conf.ucValidator.Validate(nil, nil, nil))
	require.Equal(t, t1Timeout, conf.t1Timeout)
	require.EqualValues(t, 1, conf.replicationConfig.maxFetchBlocks)
	require.EqualValues(t, 2, conf.replicationConfig.maxReturnBlocks)
	require.EqualValues(t, 1000, conf.replicationConfig.timeout)
}

func TestNewNodeConf_WithDefaults(t *testing.T) {
	keyConf, nodeInfo := createKeyConf(t)
	shardConf := &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       5,
		PartitionID:     0x01010101,
		ShardID:         types.ShardID{},
		PartitionTypeID: 999,
		TypeIDLen:       8,
		UnitIDLen:       256,
		T2Timeout:       2500 * time.Millisecond,
		Epoch:           0,
		EpochStart:      1,
		Validators:      []*types.NodeInfo{nodeInfo},
	}

	signer, _ := testsig.CreateSignerAndVerifier(t)
	trustBase := testtrustbase.NewTrustBase(t, signer)

	log := testlogger.New(t)

	shardConfStore, err := NewShardConfStore(memorydb.New(), log)
	require.NoError(t, err)
	require.NoError(t, shardConfStore.Store(shardConf))

	trustBaseStore, err := trustbase.NewTrustBaseStore(memorydb.New(), log)
	require.NoError(t, err)
	require.NoError(t, trustBaseStore.Store(trustBase))

	_, err = NewNodeConf(nil, shardConfStore, trustBaseStore)
	require.ErrorIs(t, err, ErrKeyConfIsNil)

	_, err = NewNodeConf(keyConf, nil, trustBaseStore)
	require.ErrorIs(t, err, ErrShardConfStoreIsNil)

	_, err = NewNodeConf(keyConf, shardConfStore, nil)
	require.ErrorIs(t, err, ErrTrustBaseStoreIsNil)

	conf, err := NewNodeConf(keyConf, shardConfStore, trustBaseStore)
	require.NoError(t, err)
	require.NotNil(t, conf)

	require.NotNil(t, conf.blockDB)
	require.NotNil(t, conf.signer)
	require.NotNil(t, conf.bpValidator)
	require.NotNil(t, conf.ucValidator)
	require.NotNil(t, conf.shardConf)
	require.NotNil(t, conf.hashAlgorithm)
	require.Equal(t, DefaultT1Timeout*time.Millisecond, conf.t1Timeout)
	require.Equal(t, DefaultReplicationMaxBlocks, conf.replicationConfig.maxFetchBlocks)
	require.Equal(t, DefaultReplicationMaxBlocks, conf.replicationConfig.maxReturnBlocks)
	require.Equal(t, DefaultLedgerReplicationTimeout, conf.replicationConfig.timeout)
}

func createKeyConf(t *testing.T) (*KeyConf, *types.NodeInfo) {
	privKey, _, err := p2pcrypto.GenerateSecp256k1Key(rand.Reader)
	require.NoError(t, err)

	nodeID, err := peer.IDFromPrivateKey(privKey)
	require.NoError(t, err)

	privKeyBytes, err := privKey.Raw()
	require.NoError(t, err)

	key := Key{
		Algorithm:  KeyAlgorithmSecp256k1,
		PrivateKey: privKeyBytes,
	}
	keyConf := &KeyConf{
		SigKey:  key,
		AuthKey: key,
	}
	signer, err := keyConf.Signer()
	require.NoError(t, err)
	sigVerifier, err := signer.Verifier()
	require.NoError(t, err)
	sigKey, err := sigVerifier.MarshalPublicKey()
	require.NoError(t, err)

	return keyConf, &types.NodeInfo{
		NodeID: nodeID.String(),
		SigKey: sigKey,
		Stake:  1,
	}
}
