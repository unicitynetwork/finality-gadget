package partition

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	bftcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/finality-gadget/network"
)

const (
	KeyAlgorithmSecp256k1 = "secp256k1"

	DefaultT1Timeout                       = 8640000 // 2.4h
	DefaultReplicationMaxBlocks     uint64 = 1000
	DefaultReplicationMaxWorkers    uint64 = 10
	DefaultLedgerReplicationTimeout        = 1500 * time.Millisecond
)

var (
	ErrKeyConfIsNil        = errors.New("key configuration is nil")
	ErrShardConfStoreIsNil = errors.New("shard conf store is nil")
	ErrTrustBaseStoreIsNil = errors.New("trust base store is nil")
)

type (
	NodeConf struct {
		keyConf        *KeyConf
		shardConfStore *ShardConfStore
		trustBaseStore *trustbase.TrustBaseStore

		address               string
		announceAddresses     []string
		bootstrapAddresses    []string
		bootstrapConnectRetry *network.BootstrapConnectRetry
		validatorNetwork      ValidatorNetwork

		signer           bftcrypto.Signer
		hashAlgorithm    crypto.Hash // make hash algorithm configurable in the future. currently it is using SHA-256.
		ucValidator      UnicityCertificateValidator
		bpValidator      BlockProposalValidator
		blockDB          keyvaluedb.KeyValueDB
		proofIndexConfig proofIndexConfig
		t1Timeout        time.Duration // T1 timeout of the node. Time to wait before node creates a new block proposal.

		replicationConfig ledgerReplicationConfig

		// first shardConf from shardConfStore
		shardConf *types.PartitionDescriptionRecord
	}

	NodeOption func(c *NodeConf)

	KeyConf struct {
		SigKey  Key `json:"sigKey"`
		AuthKey Key `json:"authKey"`
	}

	Key struct {
		Algorithm  string    `json:"algorithm"`
		PrivateKey hex.Bytes `json:"privateKey"`
	}

	// proofIndexConfig proof indexer config
	// store - type of store, either a memory DB or bolt DB
	// historyLen - number of rounds/blocks to keep in indexer:
	// - if 0, there is no clean-up and all blocks are kept in the index;
	// - otherwise, the latest historyLen is kept and older will be removed from the DB (sliding window).
	proofIndexConfig struct {
		db         keyvaluedb.KeyValueDB
		historyLen uint64
	}

	ledgerReplicationConfig struct {
		maxFetchBlocks  uint64
		maxReturnBlocks uint64
		maxWorkers      uint64
		timeout         time.Duration
	}
)

func NewNodeConf(
	keyConf *KeyConf,
	shardConfStore *ShardConfStore,
	trustBaseStore *trustbase.TrustBaseStore,
	nodeOptions ...NodeOption,
) (*NodeConf, error) {
	if keyConf == nil {
		return nil, ErrKeyConfIsNil
	}
	if shardConfStore == nil {
		return nil, ErrShardConfStoreIsNil
	}
	if trustBaseStore == nil {
		return nil, ErrTrustBaseStoreIsNil
	}

	shardConf, err := shardConfStore.GetFirst()
	if err != nil {
		return nil, err
	}

	signer, err := keyConf.Signer()
	if err != nil {
		return nil, err
	}

	hashAlg := crypto.SHA256

	c := &NodeConf{
		keyConf:        keyConf,
		shardConfStore: shardConfStore,
		trustBaseStore: trustBaseStore,
		blockDB:        memorydb.New(),
		signer:         signer,
		hashAlgorithm:  hashAlg,
		bpValidator:    NewDefaultBlockProposalValidator(hashAlg),
		ucValidator:    NewDefaultUnicityCertificateValidator(hashAlg),
		proofIndexConfig: proofIndexConfig{
			db:         memorydb.New(),
			historyLen: 20,
		},
		replicationConfig: ledgerReplicationConfig{
			maxFetchBlocks:  DefaultReplicationMaxBlocks,
			maxReturnBlocks: DefaultReplicationMaxBlocks,
			maxWorkers:      DefaultReplicationMaxWorkers,
			timeout:         DefaultLedgerReplicationTimeout,
		},
		t1Timeout: DefaultT1Timeout * time.Millisecond,
		shardConf: shardConf,
	}

	for _, option := range nodeOptions {
		option(c)
	}

	if c.replicationConfig.maxWorkers < 1 {
		return nil, errors.New("replication max workers must be at least 1")
	}

	return c, nil
}

func WithAddress(address string) NodeOption {
	return func(c *NodeConf) {
		c.address = address
	}
}

func WithAnnounceAddresses(announceAddresses []string) NodeOption {
	return func(c *NodeConf) {
		c.announceAddresses = announceAddresses
	}
}

func WithBootstrapAddresses(bootstrapAddresses []string) NodeOption {
	return func(c *NodeConf) {
		c.bootstrapAddresses = bootstrapAddresses
	}
}

func WithBootstrapConnectRetry(bootstrapConnectRetry *network.BootstrapConnectRetry) NodeOption {
	return func(c *NodeConf) {
		c.bootstrapConnectRetry = bootstrapConnectRetry
	}
}

func WithValidatorNetwork(validatorNetwork ValidatorNetwork) NodeOption {
	return func(c *NodeConf) {
		c.validatorNetwork = validatorNetwork
	}
}

func WithReplicationParams(maxFetchBlocks, maxReturnBlocks, maxWorkers uint64, timeout time.Duration) NodeOption {
	return func(c *NodeConf) {
		c.replicationConfig.maxFetchBlocks = maxFetchBlocks
		c.replicationConfig.maxReturnBlocks = maxReturnBlocks
		c.replicationConfig.maxWorkers = maxWorkers
		c.replicationConfig.timeout = timeout
	}
}

func WithUnicityCertificateValidator(unicityCertificateValidator UnicityCertificateValidator) NodeOption {
	return func(c *NodeConf) {
		c.ucValidator = unicityCertificateValidator
	}
}

func WithBlockProposalValidator(blockProposalValidator BlockProposalValidator) NodeOption {
	return func(c *NodeConf) {
		c.bpValidator = blockProposalValidator
	}
}

func WithBlockDB(blockDB keyvaluedb.KeyValueDB) NodeOption {
	return func(c *NodeConf) {
		c.blockDB = blockDB
	}
}

func WithT1Timeout(t1Timeout time.Duration) NodeOption {
	return func(c *NodeConf) {
		c.t1Timeout = t1Timeout
	}
}

func (c *NodeConf) ShardConf() *types.PartitionDescriptionRecord {
	return c.shardConf
}

func (c *NodeConf) TrustBaseStore() *trustbase.TrustBaseStore {
	return c.trustBaseStore
}

func (c *NodeConf) HashAlgorithm() crypto.Hash {
	return c.hashAlgorithm
}

func (c *NodeConf) BlockDB() keyvaluedb.KeyValueDB {
	return c.blockDB
}

func (c *NodeConf) PeerConf() (*network.PeerConfiguration, error) {
	authKeyPair, err := c.keyConf.AuthKeyPair()
	if err != nil {
		return nil, fmt.Errorf("invalid authentication key: %w", err)
	}

	bootNodes := make([]peer.AddrInfo, len(c.bootstrapAddresses))
	for i, addr := range c.bootstrapAddresses {
		addrInfo, err := peer.AddrInfoFromString(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid bootstrap address: %w", err)
		}
		bootNodes[i] = *addrInfo
	}

	return network.NewPeerConfiguration(c.address, c.announceAddresses, authKeyPair, bootNodes, c.bootstrapConnectRetry)
}

func (c *KeyConf) NodeID() (peer.ID, error) {
	authPrivKey, err := p2pcrypto.UnmarshalSecp256k1PrivateKey(c.AuthKey.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid authentication key: %w", err)
	}
	return peer.IDFromPrivateKey(authPrivKey)
}

func (c *KeyConf) Signer() (bftcrypto.Signer, error) {
	signer, err := bftcrypto.NewInMemorySecp256K1SignerFromKey(c.SigKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid signing key: %w", err)
	}
	return signer, nil
}

func (c *KeyConf) AuthKeyPair() (*network.PeerKeyPair, error) {
	if c.AuthKey.Algorithm != KeyAlgorithmSecp256k1 {
		return nil, fmt.Errorf("unsupported authentication key algorithm %v", c.AuthKey.Algorithm)
	}
	authPrivKey, err := p2pcrypto.UnmarshalSecp256k1PrivateKey(c.AuthKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal authentication key: %w", err)
	}
	authPrivKeyBytes, err := authPrivKey.Raw()
	if err != nil {
		return nil, err
	}
	authPubKeyBytes, err := authPrivKey.GetPublic().Raw()
	if err != nil {
		return nil, err
	}
	return &network.PeerKeyPair{
		PublicKey:  authPubKeyBytes,
		PrivateKey: authPrivKeyBytes,
	}, nil
}
