package partition

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-go-base/types"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/finality-gadget/logger"
	"github.com/unicitynetwork/finality-gadget/network"
	"github.com/unicitynetwork/finality-gadget/network/protocol/blockproposal"
	"github.com/unicitynetwork/finality-gadget/network/protocol/certification"
	"github.com/unicitynetwork/finality-gadget/network/protocol/replication"
	"github.com/unicitynetwork/finality-gadget/txsystem/state"
)

var ErrNodeDoesNotHaveLatestBlock = errors.New("recovery needed, node does not have the latest block")

type (
	// ValidatorNetwork provides an interface for sending and receiving validator network messages.
	ValidatorNetwork interface {
		Send(ctx context.Context, msg any, receivers ...peer.ID) error
		ReceivedChannel() <-chan any
		RegisterValidatorProtocols() error
	}

	// TransactionSystem is a set of rules and logic for performing state transitions.
	TransactionSystem interface {
		// StateSummary returns the summary of the current state.
		StateSummary() (*state.Summary, error)

		// LeaderPropose is called by the partition leader to propose a new block.
		LeaderPropose(ctx context.Context, round uint64) (*state.Summary, error)

		// FollowerVerify is called by followers to validate the proposed block.
		FollowerVerify(ctx context.Context, round uint64, proposedRoot []byte) (*state.Summary, error)

		// RestoreState restores the transaction system state from the given UC
		RestoreState(ctx context.Context, uc *types.UnicityCertificate) error

		// UpdateConfig updates the transaction system configuration.
		UpdateConfig(shardConf *types.PartitionDescriptionRecord) error

		// Revert signals an unsuccessful consensus round.
		Revert()

		// Commit signals a successful consensus round.
		Commit(uc *types.UnicityCertificate) error

		// CommittedUC returns the unicity certificate of the latest commit.
		CommittedUC() *types.UnicityCertificate
	}

	replicationRequest struct {
		ctx context.Context
		req *replication.LedgerReplicationRequest
	}

	roundTimer struct {
		isRunning atomic.Bool
		cancel    context.CancelFunc
		event     chan struct{}
	}

	// Node represents a member in the partition and implements an instance of a specific TransactionSystem.
	// Partition is a distributed system, it consists of either a set of shards, or one or more partition nodes.
	Node struct {
		// ---- configuration ----
		conf *NodeConf
		log  *slog.Logger

		// ---- application layer ----
		transactionSystem TransactionSystem

		// ---- consensus state ----
		state *ConsensusState

		// ---- recovery ----
		recoveryLastProp  *blockproposal.BlockProposal
		lastLedgerReqTime time.Time
		replicationCh     chan replicationRequest

		// ---- persistence ----
		blockStore     keyvaluedb.KeyValueDB
		shardConfStore *ShardConfStore
		trustBaseStore *trustbase.TrustBaseStore

		// ---- networking ----
		network ValidatorNetwork
		peer    *network.Peer

		// ---- timing ----
		timer roundTimer

		// ---- epoch management ----
		epochChangeEvent chan struct{}
		shardConf        atomic.Pointer[types.PartitionDescriptionRecord]
	}
)

func (n *Node) Run(ctx context.Context) error {
	if err := n.network.RegisterValidatorProtocols(); err != nil {
		return fmt.Errorf("failed to register validator protocols: %w", err)
	}
	n.sendHandshake(ctx)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		err := n.loop(ctx)
		n.log.DebugContext(ctx, "node main loop exit", logger.Error(err))
		return err
	})

	g.Go(func() error {
		n.replicationLoop(ctx)
		return nil
	})

	return g.Wait()
}

/*
loop runs the main loop of validator node.
It handles messages received from other AB network nodes and coordinates
timeout and communication with rootchain.
*/
func (n *Node) loop(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastUCReceived = time.Now()
	var lastBlockReceived = time.Now()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case m, ok := <-n.network.ReceivedChannel():
			if !ok {
				return errors.New("network received channel is closed")
			}
			n.log.Log(ctx, logger.LevelTrace, fmt.Sprintf("received %T", m), logger.Data(m))

			if err := n.handleMessage(ctx, m); err != nil {
				n.log.WarnContext(ctx, fmt.Sprintf("handling %T", m), logger.Error(err))
			} else if _, ok := m.(*certification.CertificationResponse); ok {
				lastUCReceived = time.Now()
			} else if _, ok := m.(*types.Block); ok {
				lastBlockReceived = time.Now()
			}
		case <-n.timer.event:
			n.handleT1TimeoutEvent(ctx)
		case <-n.epochChangeEvent:
			n.handleEpochChangeEvent(ctx)
		case <-ticker.C:
			n.handleMonitoring(ctx, lastUCReceived, lastBlockReceived)
		}

		// central location to manage T1 timeout
		n.ensureT1TimerState(ctx)
	}
}

/*
handleMessage processes message received from AB network (ie from other shard validators or root partition).
*/
func (n *Node) handleMessage(ctx context.Context, msg any) (rErr error) {
	switch mt := msg.(type) {
	case *certification.CertificationResponse:
		return n.handleCertificationResponse(ctx, mt)
	case *blockproposal.BlockProposal:
		return n.handleBlockProposal(ctx, mt)
	case *replication.LedgerReplicationRequest:
		return n.handleLedgerReplicationRequest(ctx, mt)
	case *replication.LedgerReplicationResponse:
		return n.handleLedgerReplicationResponse(ctx, mt)
	default:
		return fmt.Errorf("unknown message: %T", mt)
	}
}

func (n *Node) handleEpochChangeEvent(ctx context.Context) {
	newEpoch := n.currentEpoch()

	shardConf, err := n.shardConfStore.Get(newEpoch)
	if err != nil {
		// Log the error and let the node continue with the old configuration
		n.log.ErrorContext(ctx, fmt.Sprintf("failed to load shard configuration for epoch %d", newEpoch), logger.Error(err))
		return
	}

	n.shardConf.Store(shardConf)

	if err := n.transactionSystem.UpdateConfig(shardConf); err != nil {
		n.log.ErrorContext(ctx, fmt.Sprintf("failed to update transaction system config for epoch %d", newEpoch), logger.Error(err))
	}
}

// handleMonitoring - monitors root communication, if for no UC is
// received for a long time then try and request one from root
func (n *Node) handleMonitoring(ctx context.Context, lastUCReceived, lastBlockReceived time.Time) {
	// During application startup the initial handshake message may be lost,
	// so we retry it here, otherwise we would have to wait for T2 timeout (12h).
	if n.state.status == initializing {
		if time.Since(lastUCReceived) > 5*time.Second {
			n.log.DebugContext(ctx, "Still initializing, retrying handshake to root nodes")
			n.sendHandshake(ctx)
		}
	} else {
		// check if we have not heard from root validator for T2 timeout + 1 sec
		// a new repeat UC must have been made by now (assuming root is fine) try and get it from other root nodes
		if time.Since(lastUCReceived) > n.shardConf.Load().T2Timeout+time.Second {
			// query latest UC from root
			n.log.DebugContext(ctx, "T2 timeout exceeded without receiving UC, requesting from root nodes")
			n.sendHandshake(ctx)
		}
	}

	// handle ledger replication timeout - no response from node is received
	if n.state.status == recovering && time.Since(n.lastLedgerReqTime) > n.conf.replicationConfig.timeout {
		n.log.WarnContext(ctx, "Ledger replication timeout, repeat request")
		n.sendLedgerReplicationRequest(ctx)
	}
}

func (n *Node) NetworkID() types.NetworkID {
	return n.shardConf.Load().NetworkID
}

func (n *Node) PartitionID() types.PartitionID {
	return n.shardConf.Load().PartitionID
}

func (n *Node) PartitionTypeID() types.PartitionTypeID {
	return n.shardConf.Load().PartitionTypeID
}

func (n *Node) ShardID() types.ShardID {
	return n.shardConf.Load().ShardID
}

func (n *Node) Peer() *network.Peer {
	return n.peer
}

func (n *Node) Validators() peer.IDSlice {
	validators := n.shardConf.Load().Validators
	validatorIDs := make(peer.IDSlice, len(validators))
	for idx, validator := range validators {
		validatorID, err := peer.Decode(validator.NodeID)
		if err != nil {
			n.log.Error(fmt.Sprintf("failed to decode shard validator ID %s", validator.NodeID), logger.Error(err))
			continue
		}
		validatorIDs[idx] = validatorID
	}
	return validatorIDs
}

func (n *Node) RootValidators() (peer.IDSlice, error) {
	rootEpoch := n.latestUC().GetRootEpoch()
	trustBase, err := n.trustBaseStore.GetByEpoch(rootEpoch)
	if err != nil {
		return nil, fmt.Errorf("failed to load trust base for epoch %d: %w", rootEpoch, err)
	}

	validators := trustBase.RootNodes
	validatorIDs := make(peer.IDSlice, len(validators))
	for idx, validator := range validators {
		validatorID, err := peer.Decode(validator.NodeID)
		if err != nil {
			return nil, fmt.Errorf("failed to decode root validator ID %s: %w", validator.NodeID, err)
		}
		validatorIDs[idx] = validatorID
	}
	return validatorIDs, nil
}

func (n *Node) FilterValidatorNodes(exclude peer.ID) []peer.ID {
	var result []peer.ID
	for _, v := range n.Validators() {
		if v != exclude {
			result = append(result, v)
		}
	}
	return result
}

func printUC(uc *types.UnicityCertificate) string {
	if uc == nil {
		return ""
	}
	return fmt.Sprintf("H:\t%X\nH':\t%X\nHb:\t%X\nfees:%d, round:%d, root round:%d",
		uc.InputRecord.Hash, uc.InputRecord.PreviousHash, uc.InputRecord.BlockHash,
		uc.InputRecord.SumOfEarnedFees, uc.GetRoundNumber(), uc.GetRootRoundNumber())
}
