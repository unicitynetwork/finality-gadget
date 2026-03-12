package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/finality-gadget/internal/debug"
	"github.com/unicitynetwork/finality-gadget/logger"
	"github.com/unicitynetwork/finality-gadget/network"
	"github.com/unicitynetwork/finality-gadget/partition"
	"github.com/unicitynetwork/finality-gadget/pow"
	"github.com/unicitynetwork/finality-gadget/txsystem"
)

type cliFlags struct {
	PowSocketPath string
	HomeDir       string
	CfgFile       string
	LogCfgFile    string

	KeyConfFile    string
	ShardConfFiles []string
	TrustBaseFiles []string

	Address                    string
	AnnounceAddresses          []string
	BootstrapAddresses         []string
	BootstrapConnectRetryCount int
	BootstrapConnectRetryDelay int

	BlockDBFile     string
	ShardConfDBFile string
	TrustBaseDBFile string

	LedgerReplicationMaxBlocksFetch uint64
	LedgerReplicationMaxBlocks      uint64
	LedgerReplicationTimeoutMs      uint32
	T1TimeoutMs                     uint32
}

func newRunCmd(flags *cliFlags) *cobra.Command {
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the FGP node",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNode(cmd.Context(), flags, cmd)
		},
	}

	// Config Flags
	home, err := os.UserHomeDir()
	if err != nil {
		panic("default user home dir not defined: " + err.Error())
	}
	runCmd.Flags().StringVar(&flags.PowSocketPath, "pow-socket-path", filepath.Join(home, ".unicity", "node.sock"), "Path to PoW node RPC socket path")

	runCmd.Flags().StringVarP(&flags.KeyConfFile, "key-conf", "k", "", "path to the key configuration file (default: $FGP_HOME/keys.json)")
	runCmd.Flags().StringSliceVarP(&flags.ShardConfFiles, "shard-conf", "s", []string{}, "path to shard conf (default: $FGP_HOME/shard-conf.json)")
	runCmd.Flags().StringSliceVarP(&flags.TrustBaseFiles, "trust-base", "t", []string{}, "path to trust base (default: $FGP_HOME/trust-base.json)")

	// Node P2P Flags
	runCmd.Flags().StringVarP(&flags.Address, "address", "a", "/ip4/127.0.0.1/tcp/26652", "listen address for p2p connections (libp2p multiaddress format)")
	runCmd.Flags().StringSliceVarP(&flags.AnnounceAddresses, "announce-addresses", "", nil, "announced listen addresses (libp2p multiaddress format)")
	runCmd.Flags().StringSliceVar(&flags.BootstrapAddresses, "bootnodes", nil, "addresses of bootstrap nodes (libp2p multiaddress format)")
	runCmd.Flags().IntVar(&flags.BootstrapConnectRetryCount, "bootnode-connect-retry-count", 10, "number of times to retry connecting to bootstrap nodes")
	runCmd.Flags().IntVar(&flags.BootstrapConnectRetryDelay, "bootnode-connect-retry-delay", 1, "delay in seconds between retries for connecting to bootstrap nodes")

	// DB Flags
	runCmd.Flags().StringVar(&flags.BlockDBFile, "block-db", "", "path to the block database (default: $FGP_HOME/blocks.db)")
	runCmd.Flags().StringVar(&flags.ShardConfDBFile, "shard-db", "", "path to the shard configuration database (default: $FGP_HOME/shard.db)")
	runCmd.Flags().StringVar(&flags.TrustBaseDBFile, "trustbase-db", "", "path to the trustbase database (default: $FGP_HOME/trustbase.db)")

	// Consensus & Replication Flags
	runCmd.Flags().Uint64Var(&flags.LedgerReplicationMaxBlocksFetch, "ledger-replication-max-blocks-fetch", 1000, "maximum number of blocks to query in a single replication request")
	runCmd.Flags().Uint64Var(&flags.LedgerReplicationMaxBlocks, "ledger-replication-max-blocks", 1000, "maximum number of blocks to return in a single replication response")
	runCmd.Flags().Uint32Var(&flags.LedgerReplicationTimeoutMs, "ledger-replication-timeout", 1500, "time since last received replication response when to trigger another request (in ms)")
	runCmd.Flags().Uint32Var(&flags.T1TimeoutMs, "t1-timeout", partition.DefaultT1Timeout, "T1 timeout (consensus parameter)")

	return runCmd
}

func runNode(ctx context.Context, flags *cliFlags, cmd *cobra.Command) error {
	log, err := initLogger(flags, cmd)
	if err != nil {
		return fmt.Errorf("failed to init logger: %w", err)
	}

	keyConfPath := flags.pathWithDefault(flags.KeyConfFile, "keys.json")
	if !util.FileExists(keyConfPath) {
		return fmt.Errorf("keys file not found in: %s", keyConfPath)
	}
	var keyConf partition.KeyConf
	if err := loadConf(keyConfPath, &keyConf); err != nil {
		return fmt.Errorf("failed to load key conf: %s", keyConfPath)
	}

	nodeID, err := keyConf.NodeID()
	if err != nil {
		return fmt.Errorf("failed to calculate nodeID: %w", err)
	}
	log = log.With(logger.NodeID(nodeID))

	// Load Shard Configurations
	shardConfs := make([]*types.PartitionDescriptionRecord, 0, len(flags.ShardConfFiles))
	if len(flags.ShardConfFiles) == 0 {
		var defaultConf types.PartitionDescriptionRecord
		path := flags.pathWithDefault("", "shard-conf.json")
		if err := loadConf(path, &defaultConf); err != nil {
			return fmt.Errorf("failed to load shard conf: %w", err)
		}
		shardConfs = append(shardConfs, &defaultConf)
	} else {
		for _, file := range flags.ShardConfFiles {
			var conf types.PartitionDescriptionRecord
			if err := loadConf(file, &conf); err != nil {
				return fmt.Errorf("failed to load shard conf: %w", err)
			}
			shardConfs = append(shardConfs, &conf)
		}
	}

	shardConfDB, err := flags.initDB(flags.ShardConfDBFile, shardConfDBFileName)
	if err != nil {
		return err
	}
	shardConfStore, err := partition.NewShardConfStore(shardConfDB, log)
	if err != nil {
		return err
	}
	for _, shardConf := range shardConfs {
		if err := shardConfStore.Store(shardConf); err != nil {
			return fmt.Errorf("failed to store shard configuration: %w", err)
		}
	}

	shardConf, err := shardConfStore.GetFirst()
	if err != nil {
		return err
	}
	log = log.With(logger.Shard(shardConf.PartitionID, shardConf.ShardID))

	// Load Trust Bases
	trustBases := make([]*types.RootTrustBaseV1, 0, len(flags.TrustBaseFiles))
	if len(flags.TrustBaseFiles) == 0 {
		var defaultTB types.RootTrustBaseV1
		path := flags.pathWithDefault("", "trust-base.json")
		if err := loadConf(path, &defaultTB); err != nil {
			return fmt.Errorf("failed to load trust base: %w", err)
		}
		trustBases = append(trustBases, &defaultTB)
	} else {
		for _, file := range flags.TrustBaseFiles {
			var tb types.RootTrustBaseV1
			if err := loadConf(file, &tb); err != nil {
				return fmt.Errorf("failed to load trust base: %w", err)
			}
			trustBases = append(trustBases, &tb)
		}
	}

	trustBaseDB, err := flags.initDB(flags.TrustBaseDBFile, "trustbase.db")
	if err != nil {
		return err
	}
	trustBaseStore, err := trustbase.NewTrustBaseStore(trustBaseDB, log)
	if err != nil {
		return fmt.Errorf("failed to create trust base store: %w", err)
	}
	for _, trustBase := range trustBases {
		if err := trustBaseStore.Store(trustBase); err != nil {
			if !errors.Is(err, trustbase.ErrAlreadyExists) {
				return fmt.Errorf("failed to store trust base: %w", err)
			}
			log.Warn(fmt.Sprintf("trust base already exists for epoch %d, not overwriting it", trustBase.Epoch))
		}
	}

	blockDB, err := flags.initDB(flags.BlockDBFile, blockDBFileName)
	if err != nil {
		return err
	}

	bootstrapConnectRetry := &network.BootstrapConnectRetry{
		Count: flags.BootstrapConnectRetryCount,
		Delay: flags.BootstrapConnectRetryDelay,
	}

	nodeConf, err := partition.NewNodeConf(
		&keyConf,
		shardConfStore,
		trustBaseStore,
		partition.WithAddress(flags.Address),
		partition.WithAnnounceAddresses(flags.AnnounceAddresses),
		partition.WithBootstrapAddresses(flags.BootstrapAddresses),
		partition.WithBootstrapConnectRetry(bootstrapConnectRetry),
		partition.WithBlockDB(blockDB),
		partition.WithReplicationParams(flags.LedgerReplicationMaxBlocksFetch, flags.LedgerReplicationMaxBlocks, time.Duration(flags.LedgerReplicationTimeoutMs)*time.Millisecond),
		partition.WithT1Timeout(time.Duration(flags.T1TimeoutMs)*time.Millisecond),
	)
	if err != nil {
		return fmt.Errorf("failed to create node configuration: %w", err)
	}

	powClient := pow.NewIPCClient(flags.PowSocketPath)
	txSystem, err := txsystem.NewFGPTxSystem(*shardConf, powClient, log)
	if err != nil {
		return fmt.Errorf("failed to create FGP tx system: %w", err)
	}

	node, err := partition.NewNode(ctx, txSystem, nodeConf, log)
	if err != nil {
		return err
	}

	log.InfoContext(ctx, fmt.Sprintf("starting FGP node: BuildInfo=%s", debug.ReadBuildInfo()))
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return node.Run(ctx) })

	return g.Wait()
}

func (f *cliFlags) pathWithDefault(path string, defaultFileName string) string {
	if path != "" {
		return path
	}
	return filepath.Join(f.HomeDir, defaultFileName)
}

func (f *cliFlags) initDB(path string, defaultFileName string) (keyvaluedb.KeyValueDB, error) {
	path = f.pathWithDefault(path, defaultFileName)
	db, err := boltdb.New(path)
	if err != nil {
		return nil, fmt.Errorf("failed to init %q: %w", path, err)
	}
	return db, nil
}
