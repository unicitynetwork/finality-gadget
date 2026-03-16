package partition

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/finality-gadget/logger"
	"github.com/unicitynetwork/finality-gadget/network"
)

/*
NewNode creates a new instance of the partition node.

The following restrictions apply to the inputs:
  - the network peer and signer must use the same keys that were used to generate node genesis file;
*/
func NewNode(ctx context.Context, txSystem TransactionSystem, conf *NodeConf, log *slog.Logger) (*Node, error) {
	peerConf, err := conf.PeerConf()
	if err != nil {
		return nil, fmt.Errorf("failed to create peer configuration: %w", err)
	}

	n := &Node{
		conf:              conf,
		transactionSystem: txSystem,
		blockStore:        conf.blockDB,
		state:             &ConsensusState{status: initializing},
		timer: roundTimer{
			event: make(chan struct{}, 1),
		},
		epochChangeEvent:  make(chan struct{}, 1),
		shardConfStore:    conf.shardConfStore,
		trustBaseStore:    conf.trustBaseStore,
		network:           conf.validatorNetwork,
		lastLedgerReqTime: time.Time{},
		log:               log,
	}
	n.timer.stop.Store(func() {})

	shardConf, err := n.shardConfStore.GetFirst()
	if err != nil {
		return nil, fmt.Errorf("failed to load initial shard conf: %w", err)
	}
	n.shardConf.Store(shardConf)

	n.log.InfoContext(ctx, fmt.Sprintf("Node '%s' initializing, starting round #%d", peerConf.ID, txSystem.CommittedUC().GetRoundNumber()))

	if err = n.initState(ctx); err != nil {
		return nil, fmt.Errorf("node state initialization failed: %w", err)
	}

	if err = n.initNetwork(ctx, peerConf); err != nil {
		return nil, fmt.Errorf("node network initialization failed: %w", err)
	}

	return n, nil
}

func (n *Node) initState(ctx context.Context) (err error) {
	dbIt := n.blockStore.Last()
	defer func() {
		if err := dbIt.Close(); err != nil {
			n.log.WarnContext(ctx, "closing DB iterator", logger.Error(err))
		}
	}()

	if dbIt.Valid() {
		var b types.Block
		if err = dbIt.Value(&b); err != nil {
			return fmt.Errorf("failed to read latest block from db: %w", err)
		}

		uc, err := getUCv1(&b)
		if err != nil {
			return fmt.Errorf("failed to extract UC from latest block: %w", err)
		}

		shardConf, err := n.shardConfStore.Get(uc.GetShardEpoch())
		if err != nil {
			return fmt.Errorf("failed to load shard conf for epoch %d: %w", uc.GetShardEpoch(), err)
		}
		n.shardConf.Store(shardConf)

		if err = n.transactionSystem.RestoreState(ctx, uc); err != nil {
			return fmt.Errorf("failed to restore transaction system state: %w", err)
		}
	}

	// Genesis state has not been committed with a UC, so fuc/luc can be nil initially.
	n.state.fuc = n.committedUC()
	n.state.luc = n.state.fuc

	n.log.InfoContext(ctx, fmt.Sprintf("State initialized from persistent store up to round %d", n.committedUC().GetRoundNumber()))
	n.restoreBlockProposal(ctx)

	return nil
}

func (n *Node) initNetwork(ctx context.Context, peerConf *network.PeerConfiguration) error {
	var err error
	n.peer, err = network.NewPeer(ctx, peerConf, n.log)
	if err != nil {
		return err
	}
	if n.network != nil {
		return nil
	}

	n.network, err = network.NewLibP2PValidatorNetwork(ctx, n, network.DefaultValidatorNetworkOptions, n.log)
	if err != nil {
		return err
	}

	// Open a connection to the bootstrap nodes.
	// This is the only way to discover other peers, so let's do this as soon as possible.
	if err := n.peer.BootstrapConnect(ctx, n.log); err != nil {
		return err
	}
	return nil
}

func (n *Node) restoreBlockProposal(ctx context.Context) {
	pr, found, err := n.loadPendingProposal()
	if err != nil {
		n.log.ErrorContext(ctx, "Error fetching block proposal", logger.Error(err))
		return
	}
	if !found {
		n.log.DebugContext(ctx, "No pending block proposal stored")
		return
	}
	uc, err := getUCv1(pr)
	if err != nil {
		n.log.WarnContext(ctx, "Error unmarshaling unicity certificate", logger.Error(err))
		return
	}
	// make sure proposal extends the committed state
	if !bytes.Equal(n.committedUC().GetStateHash(), uc.GetPreviousStateHash()) {
		n.log.DebugContext(ctx, "Stored block proposal does not extend previous state, stale proposal")
		return
	}
	// apply stored proposal to current state
	n.log.DebugContext(ctx, "Stored block proposal extends the previous state")

	state, err := n.transactionSystem.FollowerVerify(ctx, uc.GetRoundNumber(), uc.InputRecord.Hash)
	if err != nil {
		n.log.WarnContext(ctx, "Block proposal recovery failed", logger.Error(err))
		n.revertState()
		return
	}
	if err = state.EqualsIR(uc.InputRecord); err != nil {
		n.log.WarnContext(ctx, fmt.Sprintf("Block proposal recovery failed, state mismatch: %v", err))
		n.revertState()
		return
	}
	// wait for UC to certify the block proposal
	n.state.pendingBlockProposal = pr
}
