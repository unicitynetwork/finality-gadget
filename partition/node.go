package partition

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/finality-gadget/logger"
	"github.com/unicitynetwork/finality-gadget/network"
	"github.com/unicitynetwork/finality-gadget/network/protocol/blockproposal"
	"github.com/unicitynetwork/finality-gadget/network/protocol/certification"
	"github.com/unicitynetwork/finality-gadget/network/protocol/handshake"
	"github.com/unicitynetwork/finality-gadget/network/protocol/replication"
	"github.com/unicitynetwork/finality-gadget/txsystem"
)

const (
	initializing status = iota
	normal
	recovering
)

func (s status) String() string {
	switch s {
	case initializing:
		return "initializing"
	case normal:
		return "normal"
	case recovering:
		return "recovering"
	default:
		return fmt.Sprintf("status(%d)", int(s))
	}
}

// Key 0 is used for proposal, that way it is still possible to reverse iterate the DB
// and use 4 byte key, make it incompatible with block number
const proposalKey = uint32(0)

var ErrNodeDoesNotHaveLatestBlock = errors.New("recovery needed, node does not have the latest block")

type (
	// ValidatorNetwork provides an interface for sending and receiving validator network messages.
	ValidatorNetwork interface {
		Send(ctx context.Context, msg any, receivers ...peer.ID) error
		ReceivedChannel() <-chan any
		RegisterValidatorProtocols() error
	}

	// Node represents a member in the partition and implements an instance of a specific TransactionSystem.
	// Partition is a distributed system, it consists of either a set of shards, or one or more partition nodes.
	Node struct {
		status            atomic.Value
		conf              *NodeConf
		transactionSystem txsystem.TransactionSystem

		// First UC for this node. The node is guaranteed to have blocks starting at fuc+1.
		// If node is started from genesis, then fuc remains nil (round == 0).
		fuc *types.UnicityCertificate

		// Latest UC this node has seen. Can be ahead of the committed UC during recovery.
		luc atomic.Pointer[types.UnicityCertificate]

		// TR corresponding to the latest UC this node has seen (as referenced by luc.TRHash).
		// Can be nil if latest UC was received with a block (recovery or block propagation protocols).
		ltr atomic.Pointer[certification.TechnicalRecord]

		pendingBlockProposal *types.Block
		leader               Leader
		blockStore           keyvaluedb.KeyValueDB
		stopT1Timer          atomic.Value
		t1event              chan struct{}
		epochChangeEvent     chan struct{}
		peer                 *network.Peer

		shardConf         atomic.Pointer[types.PartitionDescriptionRecord] // current shard conf
		shardConfStore    *ShardConfStore
		trustBaseStore    *trustbase.TrustBaseStore
		network           ValidatorNetwork
		lastLedgerReqTime time.Time
		recoveryLastProp  *blockproposal.BlockProposal

		log *slog.Logger
	}

	RoundInfo struct {
		RoundNumber uint64 `json:"roundNumber"`
		EpochNumber uint64 `json:"epochNumber"`
	}

	status int
)

/*
NewNode creates a new instance of the partition node.

The following restrictions apply to the inputs:
  - the network peer and signer must use the same keys that were used to generate node genesis file;
*/
func NewNode(ctx context.Context, txSystem txsystem.TransactionSystem, conf *NodeConf, log *slog.Logger) (*Node, error) {
	peerConf, err := conf.PeerConf()
	if err != nil {
		return nil, fmt.Errorf("failed to create peer configuration: %w", err)
	}

	n := &Node{
		conf:              conf,
		transactionSystem: txSystem,
		blockStore:        conf.blockDB,
		t1event:           make(chan struct{}), // do not buffer!
		epochChangeEvent:  make(chan struct{}, 1),
		shardConfStore:    conf.shardConfStore,
		trustBaseStore:    conf.trustBaseStore,
		network:           conf.validatorNetwork,
		lastLedgerReqTime: time.Time{},
		log:               log,
	}
	n.stopT1Timer.Store(func() {})
	n.status.Store(initializing)

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

func (n *Node) Run(ctx context.Context) error {
	if err := n.network.RegisterValidatorProtocols(); err != nil {
		n.log.ErrorContext(ctx, "Failed to register validator protocols", logger.Error(err))
	}
	n.sendHandshake(ctx)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		err := n.loop(ctx)
		n.log.DebugContext(ctx, "node main loop exit", logger.Error(err))
		return err
	})

	return g.Wait()
}

func (n *Node) initState(ctx context.Context) (err error) {
	// Genesis state has not been committed with a UC, so fuc/luc can be nil initially.
	n.fuc = n.committedUC()
	n.luc.Store(n.fuc)

	// Apply blocks that build on the loaded state. Never look further back from this starting point.
	dbIt := n.blockStore.Find(util.Uint64ToBytes(n.fuc.GetRoundNumber() + 1))
	defer func() { err = errors.Join(err, dbIt.Close()) }()
	for ; dbIt.Valid(); dbIt.Next() {
		var b types.Block
		roundNo := util.BytesToUint64(dbIt.Key())
		if err = dbIt.Value(&b); err != nil {
			return fmt.Errorf("failed to read block %v from db: %w", roundNo, err)
		}
		if err = n.handleBlock(ctx, &b); err != nil {
			return fmt.Errorf("failed to handle block %v: %w", roundNo, err)
		}
	}

	n.log.InfoContext(ctx, fmt.Sprintf("State initialized from persistent store up to round %d", n.committedUC().GetRoundNumber()))
	n.restoreBlockProposal(ctx)

	return err
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

func (n *Node) committedUC() *types.UnicityCertificate {
	return n.transactionSystem.CommittedUC()
}

func (n *Node) currentEpoch() uint64 {
	ltr := n.ltr.Load()
	if ltr != nil {
		return ltr.Epoch
	}

	// If we miss LTR then LUC is our best knowledge of current epoch
	luc := n.luc.Load()
	if luc != nil {
		return luc.InputRecord.Epoch
	}

	return 0
}

func (n *Node) currentRoundNumber() uint64 {
	ltr := n.ltr.Load()
	if ltr != nil {
		return ltr.Round
	}
	// If we miss LTR then LUC is our best knowledge of current round
	return n.luc.Load().GetRoundNumber() + 1
}

func (n *Node) sendHandshake(ctx context.Context) {
	// select some random root nodes
	rootValidators, err := n.RootValidators()
	if err != nil {
		n.log.WarnContext(ctx, "selecting root nodes for handshake", logger.Error(err))
		return
	}
	rootIDs, err := randomNodeSelector(rootValidators, defaultHandshakeNodes)
	if err != nil {
		// error should only happen in case the root nodes are not initialized
		n.log.WarnContext(ctx, "selecting root nodes for handshake", logger.Error(err))
		return
	}
	if err = n.network.Send(ctx,
		handshake.Handshake{
			PartitionID: n.PartitionID(),
			ShardID:     n.ShardID(),
			NodeID:      n.peer.ID().String(),
		},
		rootIDs...); err != nil {
		n.log.WarnContext(ctx, "error sending handshake", logger.Error(err))
	}
}

func verifyTxSystemState(state *txsystem.StateSummary, ucIR *types.InputRecord) error {
	if ucIR == nil {
		return errors.New("unicity certificate input record is nil")
	}
	if !bytes.Equal(ucIR.Hash, state.Root()) {
		return fmt.Errorf("transaction system state %X is not equal to unicity certificate value %X", state.Root(), ucIR.Hash)
	}
	if !bytes.Equal(ucIR.SummaryValue, state.SummaryValue()) {
		return fmt.Errorf("transaction system summary value %X not equal to unicity certificate value %X", state.SummaryValue(), ucIR.SummaryValue)
	}
	if ucIR.SumOfEarnedFees != state.SumOfEarnedFees() {
		return fmt.Errorf("transaction system sum of earned fees %d not equal to unicity certificate value %d", state.SumOfEarnedFees(), ucIR.SumOfEarnedFees)
	}
	if !bytes.Equal(ucIR.ETHash, state.ETHash()) {
		return fmt.Errorf("transaction system executed transactions buffer hash '%X' not equal to unicity certificate value '%X'", state.ETHash(), ucIR.ETHash)
	}
	return nil
}

func getUCv1(b *types.Block) (*types.UnicityCertificate, error) {
	if b == nil {
		return nil, errors.New("block is nil")
	}
	if b.UnicityCertificate == nil {
		return nil, errors.New("block unicity certificate is nil")
	}
	uc := &types.UnicityCertificate{Version: 1}
	return uc, types.Cbor.Unmarshal(b.UnicityCertificate, uc)
}

func (n *Node) restoreBlockProposal(ctx context.Context) {
	pr := &types.Block{}
	found, err := n.blockStore.Read(util.Uint32ToBytes(proposalKey), pr)
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

	state, err := n.transactionSystem.ApplyBlock(uc.GetRoundNumber(), uc.InputRecord.Hash)
	if err != nil {
		n.log.WarnContext(ctx, "Block proposal recovery failed", logger.Error(err))
		n.revertState()
		return
	}
	if err = verifyTxSystemState(state, uc.InputRecord); err != nil {
		n.log.WarnContext(ctx, fmt.Sprintf("Block proposal recovery failed, state mismatch: %v", err))
		n.revertState()
		return
	}
	// wait for UC to certify the block proposal
	n.pendingBlockProposal = pr
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
		case <-n.t1event:
			n.handleT1TimeoutEvent(ctx)
		case <-n.epochChangeEvent:
			n.handleEpochChangeEvent(ctx)
		case <-ticker.C:
			n.handleMonitoring(ctx, lastUCReceived, lastBlockReceived)
		}
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

// handleBlockProposal processes a block proposals. Performs the following steps:
//  1. Block proposal as a whole is validated:
//     * It must have valid signature, correct transaction partition ID, valid UC;
//     * the UC must be not older than the latest known by current node;
//     * Sender must be the leader for the round started by included UC.
//  2. If included UC is newer than latest UC then the new UC is processed; this rolls back possible pending change in
//     the transaction system. If new UC is ‘repeat UC’ then update is reasonably fast; if recovery is necessary then
//     likely it takes some time and there is no reason to finish the processing of current proposal.
//  3. If the transaction system root is not equal to one extended by the processed proposal then processing is aborted.
//  4. All transaction orders in proposal are validated; on encountering an invalid transaction order the processing is
//     aborted.
//  5. Transaction orders are executed by applying them to the transaction system.
//  6. Pending unicity certificate request data structure is created and persisted.
//  7. Certificate Request query is assembled and sent to the Root Chain.
func (n *Node) handleBlockProposal(ctx context.Context, prop *blockproposal.BlockProposal) error {
	if n.status.Load() == recovering {
		// but remember last block proposal received
		n.recoveryLastProp = prop
		return fmt.Errorf("node is in recovery status")
	}
	if prop == nil {
		return blockproposal.ErrBlockProposalIsNil
	}

	trustBase, err := n.trustBaseStore.GetByEpoch(prop.UnicityCertificate.GetRootEpoch())
	if err != nil {
		return fmt.Errorf("failed to load trust base for block proposal validation: %w", err)
	}

	// Let's not verify shardConfHash inside the UC of BlockProposal,
	// we might not have the shardConf for it.
	if err := n.conf.bpValidator.Validate(prop, n.shardConf.Load(), trustBase); err != nil {
		return fmt.Errorf("block proposal validation failed, %w", err)
	}
	n.log.DebugContext(ctx, fmt.Sprintf("Handling block proposal, its UC IR Hash %X, Block hash %X",
		prop.UnicityCertificate.InputRecord.Hash, prop.UnicityCertificate.InputRecord.BlockHash))
	uc := prop.UnicityCertificate
	luc := n.luc.Load()

	// UC must not be older than the last one seen
	if uc.GetRootRoundNumber() < luc.GetRootRoundNumber() {
		return fmt.Errorf("stale block proposal with UC from root round %v, LUC root round %v",
			uc.GetRootRoundNumber(), luc.GetRootRoundNumber())
	}

	// UC can be newer than the last one seen
	if uc.GetRootRoundNumber() > luc.GetRootRoundNumber() {
		// either the other node received it faster from root or there must be some issue with root communication?
		n.log.DebugContext(ctx, fmt.Sprintf("Received newer UC with root round %d via block proposal, LUC root round %d",
			uc.GetRootRoundNumber(), luc.GetRootRoundNumber()))
		if err := n.handleUnicityCertificate(ctx, uc, &prop.Technical); err != nil {
			return fmt.Errorf("block proposal UC handling failed: %w", err)
		}
	}

	// Leader must be the author of the proposal
	expectedLeader := n.leader.Get()
	if expectedLeader == UnknownLeader || prop.NodeID != expectedLeader {
		return fmt.Errorf("expecting leader %v, leader in proposal: %v", expectedLeader, prop.NodeID)
	}

	txState, err := n.transactionSystem.StateSummary()
	if err != nil {
		return fmt.Errorf("transaction system state error, %w", err)
	}
	// Check previous state matches before applying new block.
	// Initial UC contains a nil state hash and needs not to match.
	if !uc.IsInitial() && !bytes.Equal(uc.GetStateHash(), txState.Root()) {
		return fmt.Errorf("transaction system start state mismatch error, expected: %X, got: %X", txState.Root(), uc.GetStateHash())
	}

	stateSummary, err := n.transactionSystem.ApplyBlock(n.currentRoundNumber(), txState.Root())
	if err != nil {
		n.revertState()
		return fmt.Errorf("failed to apply block: %w", err)
	}
	if err = n.sendCertificationRequest(ctx, prop.NodeID.String(), stateSummary); err != nil {
		return fmt.Errorf("certification request send failed, %w", err)
	}
	return nil
}

// Validates the given UC and sets it as the new LUC. Returns an error
// if the UC did not qualify as the new LUC and the node is not in recovery mode.
func (n *Node) updateLUC(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	if uc == nil {
		return fmt.Errorf("unicity certificate is nil")
	}

	trustBase, err := n.trustBaseStore.GetByEpoch(uc.GetRootEpoch())
	if err != nil {
		return fmt.Errorf("failed to load trust base for UC validation: %w", err)
	}

	// UC is validated cryptographically.
	// TR has already been validated to match the hash in UC
	// when receiving a CertificationResponse or a BlockProposal.
	if err := n.conf.ucValidator.Validate(uc, n.shardConf.Load(), trustBase); err != nil {
		return fmt.Errorf("certificate invalid, %w", err)
	}

	luc := n.luc.Load()
	if n.status.Load() == recovering && luc.GetRootRoundNumber() > uc.GetRootRoundNumber() {
		// During recovery, UC from a recovered block is usually older than the LUC.
		// Do not attempt to update LUC in that case.
		return nil
	}

	if n.status.Load() != initializing {
		n.log.DebugContext(ctx, fmt.Sprintf("LUC:\n%s\n\nReceived UC:\n%s", printUC(luc), printUC(uc)))
	}

	// check for equivocation
	// Skip this check if LUC is missing. LUC can only miss if node was started with an uncertified state (likely genesis).
	if luc != nil {
		if err := types.CheckNonEquivocatingCertificates(luc, uc); err != nil {
			// this is not normal, log all info
			n.log.WarnContext(ctx, fmt.Sprintf("equivocating UC for round %d", uc.InputRecord.RoundNumber), logger.Error(err), logger.Data(uc))
			n.log.WarnContext(ctx, "LUC", logger.Data(luc))
			return fmt.Errorf("equivocating certificate: %w", err)
		}
	}

	if uc.IsDuplicate(luc) && n.ltr.Load() != nil {
		// It's OK to receive duplicates, just no need to update luc/ltr if we have both
		return nil
	}

	prevEpoch := n.currentEpoch()
	if tr != nil {
		leaderPeerID, err := peer.Decode(tr.Leader)
		if err != nil {
			return fmt.Errorf("decoding leader peerID from %q: %w", tr.Leader, err)
		}
		n.leader.Set(leaderPeerID)
		n.ltr.Store(tr)
		n.log.DebugContext(ctx, "updated LTR")
	} else {
		n.leader.Set(UnknownLeader)
		n.ltr.Store(nil)
		n.log.DebugContext(ctx, "missing LTR")
	}

	n.luc.Store(uc)
	n.log.DebugContext(ctx, fmt.Sprintf("updated LUC; UC.Round: %d, RootRound: %d", uc.GetRoundNumber(), uc.GetRootRoundNumber()))

	newEpoch := n.currentEpoch()
	// Either epoch has changed or we have not managed to load the correct configuration for the epoch yet
	if prevEpoch != newEpoch || n.shardConf.Load().Epoch != newEpoch {
		// Schedule epoch change. The handling of current message is finished with the old configuration.
		// This might be problematic if epoch change is triggered by a TR in BlockProposal, which should
		// be validated according to the new epoch configuration already.
		select {
		case n.epochChangeEvent <- struct{}{}:
		default:
		}
	}

	return nil
}

func (n *Node) startNewRound(ctx context.Context) error {
	n.resetProposal()
	// not a fatal issue, but log anyway
	if err := n.blockStore.Delete(util.Uint32ToBytes(proposalKey)); err != nil {
		n.log.DebugContext(ctx, "DB proposal delete failed", logger.Error(err))
	}

	n.startT1Timer(ctx)

	return nil
}

func (n *Node) startT1Timer(ctx context.Context) {
	// stop existing timer
	n.stopT1Timer.Load().(func())()

	txCtx, txCancel := context.WithCancel(ctx)
	n.stopT1Timer.Store(func() { txCancel() })

	go func() {
		select {
		case <-time.After(n.conf.t1Timeout):
			// Rather than call handleT1TimeoutEvent directly send signal to main
			// loop - helps to avoid concurrency issues with (repeat) UC handling.
			select {
			case n.t1event <- struct{}{}:
			case <-txCtx.Done():
			}
		case <-txCtx.Done():
		}
	}()
}

func (n *Node) startRecovery(ctx context.Context) {
	if n.status.Load() == recovering {
		n.log.DebugContext(ctx, "Recovery already in progress")
		return
	}
	// starting recovery
	n.status.Store(recovering)
	n.revertState()
	n.resetProposal()

	fromBlockNr := n.committedUC().GetRoundNumber() + 1
	n.log.DebugContext(ctx, fmt.Sprintf("Entering recovery state, recover node from %d up to round %d",
		fromBlockNr, n.luc.Load().GetRoundNumber()))
	n.sendLedgerReplicationRequest(ctx)
}

func (n *Node) stopRecovery(ctx context.Context) {
	committedBlock := n.committedUC().GetRoundNumber()
	n.log.InfoContext(ctx, fmt.Sprintf("Recovery complete, committed block %d", committedBlock))
	n.status.Store(normal)
}

func (n *Node) isRecoveryComplete() bool {
	return n.committedUC().GetRoundNumber() == n.luc.Load().GetRoundNumber()
}

func (n *Node) handleCertificationResponse(ctx context.Context, cr *certification.CertificationResponse) error {
	if err := cr.IsValid(); err != nil {
		return fmt.Errorf("invalid CertificationResponse: %w", err)
	}
	n.log.InfoContext(ctx, fmt.Sprintf("handleCertificationResponse: UC round %d, next round %d, next leader %s",
		cr.UC.GetRoundNumber(), cr.Technical.Round, cr.Technical.Leader))

	if cr.Partition != n.PartitionID() || !cr.Shard.Equal(n.ShardID()) {
		return fmt.Errorf("got CertificationResponse for a wrong shard %s - %s", cr.Partition, cr.Shard)
	}

	return n.handleUnicityCertificate(ctx, &cr.UC, &cr.Technical)
}

// handleUnicityCertificate processes the Unicity Certificate and finalizes a block. Performs the following steps:
//  1. Given UC is validated cryptographically -> checked before this method is called by unicityCertificateValidator
//  2. Given UC has correct partition identifier -> checked before this method is called by unicityCertificateValidator
//  3. TODO: sanity check timestamp
//  4. Given UC is checked for equivocation (for more details see certificates.CheckNonEquivocatingCertificates)
//  5. On unexpected case where there is no pending block proposal, recovery is initiated, unless the state is already
//     up-to-date with the given UC.
//  6. Alternatively, if UC certifies the pending block proposal then block is finalized.
//  7. Alternatively, if UC certifies repeat IR (‘repeat UC’) then
//     state is rolled back to previous state.
//  8. Alternatively, recovery is initiated, after rollback. Note that recovery may end up with
//     newer last known UC than the one being processed.
//  9. New round is started.
//
// See algorithm 5 "Processing a received Unicity Certificate" in Yellowpaper for more details
func (n *Node) handleUnicityCertificate(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	prevLUC := n.luc.Load()

	if err := n.updateLUC(ctx, uc, tr); err != nil {
		return fmt.Errorf("failed to update LUC: %w", err)
	}

	// We have a new or a duplicate luc, let's see what we should do.
	if n.status.Load() == recovering {
		// Doesn't really matter what we got, recovery will handle it.
		n.log.DebugContext(ctx, "Recovery already in progress")
		return nil
	}

	wasInitializing := n.status.Load() == initializing
	if wasInitializing {
		// First UC received after an initial handshake with a root node -> initialization finished.
		n.status.Store(normal)
	}

	if uc.IsDuplicate(prevLUC) {
		// Just ignore duplicates.
		n.log.DebugContext(ctx, fmt.Sprintf("duplicate UC (same root round %d)", uc.GetRootRoundNumber()))
		if wasInitializing {
			// If this was the first UC received by node, we can start a new round.
			// Otherwise the round is already in progress.
			return n.startNewRound(ctx)
		}
		return nil
	}

	if b, err := uc.IsRepeat(prevLUC); b || err != nil {
		if err != nil {
			return fmt.Errorf("failed to check for repeat UC: %w", err)
		}
		// UC certifies the IR before pending block proposal ("repeat UC"). state is rolled back to previous state.
		n.log.WarnContext(ctx, fmt.Sprintf("Reverting state tree on repeat certificate. UC IR hash: %X", uc.GetStateHash()))
		n.revertState()
		return n.startNewRound(ctx)
	}

	committedUC := n.committedUC()
	if !uc.IsSuccessor(committedUC) {
		// Do not allow gaps between blocks, even if state hash does not change.
		n.log.WarnContext(ctx, fmt.Sprintf("Recovery needed, missing blocks. UC previous state hash %X, committed state hash %X",
			uc.GetPreviousStateHash(), committedUC.GetStateHash()))
		n.startRecovery(ctx)
		return ErrNodeDoesNotHaveLatestBlock
	}

	// If there is no pending block proposal i.e. no certification request has been sent by the node
	// - leader was down and did not make a block proposal?
	// - node did not receive a block proposal because it was down, it was not sent or there were network issues
	// Note, if for any reason the node misses the proposal and other validators finalize _one_ empty block,
	// this node will start a new round (the one that has been already finalized).
	// Eventually it will start the recovery and catch up.
	if n.pendingBlockProposal == nil {
		// Initial UC has nil state hash, and it can be different from the calculated state hash, no need to recover.
		if uc.IsInitial() {
			n.log.DebugContext(ctx, "Initial UC received, start new round to certify genesis state")
			return n.startNewRound(ctx)
		}

		// Start recovery unless the state is already up-to-date with UC.
		state, err := n.transactionSystem.StateSummary()
		if err != nil {
			n.startRecovery(ctx)
			return fmt.Errorf("recovery needed, failed to get transaction system state: %w", err)
		}
		// if state hash does not match - start recovery
		if !bytes.Equal(uc.GetStateHash(), state.Root()) {
			n.log.DebugContext(ctx, fmt.Sprintf("No pending block proposal, state hash mismatch: expected '%X' got '%X'", uc.GetStateHash(), state.Root()))
			n.startRecovery(ctx)
			return ErrNodeDoesNotHaveLatestBlock
		}
		// if executed transactions buffer hash does not match - start recovery e.g.
		// if ETBuffer contains a failed tx then state hash is the same but ETBuffer hash is different
		if !bytes.Equal(uc.GetETHash(), state.ETHash()) {
			n.log.DebugContext(ctx, fmt.Sprintf("No pending block proposal, ETBuffer hash mismatch: expected '%X' got '%X'", uc.GetETHash(), state.ETHash()))
			n.startRecovery(ctx)
			return ErrNodeDoesNotHaveLatestBlock
		}
		n.log.DebugContext(ctx, "No pending block proposal, UC IR hash is equal to State hash, so are block hashes")
		return n.startNewRound(ctx)
	}

	proposedIR, err := n.pendingBlockProposal.InputRecord()
	if err != nil {
		n.log.WarnContext(ctx, fmt.Sprintf("Invalid block proposal: %v", err))
		n.startRecovery(ctx)
		return ErrNodeDoesNotHaveLatestBlock
	}
	// Check pending block proposal
	n.log.DebugContext(ctx, fmt.Sprintf("Proposed record: %s", proposedIR))
	if err := types.AssertEqualIR(proposedIR, uc.InputRecord); err != nil {
		n.log.WarnContext(ctx, fmt.Sprintf("Recovery needed, received UC does not match proposed: %v", err))
		// UC with different IR hash. Node does not have the latest state. Revert changes and start recovery.
		// revertState is called from startRecovery()
		n.startRecovery(ctx)
		return ErrNodeDoesNotHaveLatestBlock
	}
	// replace UC
	n.pendingBlockProposal.UnicityCertificate, err = types.Cbor.Marshal(uc)
	if err != nil {
		return fmt.Errorf("failed to marshal unicity certificate: %w", err)
	}
	// UC certifies pending block proposal
	if err := n.finalizeBlock(ctx, n.pendingBlockProposal, uc); err != nil {
		n.startRecovery(ctx)
		return fmt.Errorf("block %v finalize failed: %w", uc.GetRoundNumber(), err)
	}

	return n.startNewRound(ctx)
}

func (n *Node) revertState() {
	n.log.Warn("Reverting state")
	n.transactionSystem.Revert()
}

// finalizeBlock creates the block and adds it to the blockStore.
func (n *Node) finalizeBlock(ctx context.Context, b *types.Block, uc *types.UnicityCertificate) error {
	blockNumber := uc.GetRoundNumber()
	roundNoInBytes := util.Uint64ToBytes(blockNumber)
	isInitializing := n.status.Load() == initializing

	if !isInitializing {
		// persist the block _before_ committing to tx system
		// if write fails but the round is committed in tx system, there's no way back,
		// but if commit fails, we just remove the block from the store
		if err := n.blockStore.Write(roundNoInBytes, b); err != nil {
			return fmt.Errorf("db write failed, %w", err)
		}
	}

	if err := n.transactionSystem.Commit(uc); err != nil {
		err = fmt.Errorf("unable to finalize block %d: %w", blockNumber, err)

		if !isInitializing {
			if err2 := n.blockStore.Delete(roundNoInBytes); err2 != nil {
				err = errors.Join(err, fmt.Errorf("unable to delete block %d from store: %w", blockNumber, err2))
			}
		}
		return err
	}

	return nil
}

func (n *Node) handleT1TimeoutEvent(ctx context.Context) {
	n.stopT1Timer.Load().(func())()

	if n.status.Load() == recovering {
		n.log.InfoContext(ctx, "T1 timeout: node is recovering")
		return
	}
	n.log.InfoContext(ctx, "Handling T1 timeout")
	// if node is not leader, then do not do anything
	if !n.leader.IsLeader(n.peer.ID()) {
		n.log.DebugContext(ctx, "Current node is not the leader.")
		return
	}

	n.log.DebugContext(ctx, "Current node is the leader.")
	if err := n.sendBlockProposal(ctx); err != nil {
		n.log.WarnContext(ctx, "Failed to send BlockProposal", logger.Error(err))
		return
	}

	// transition state for the current round
	// TODO fetch PoW hash from PoW node, use the same hash as genesis for now
	powHash := sha256.Sum256(nil)
	stateSummary, err := n.transactionSystem.ApplyBlock(n.currentRoundNumber(), powHash[:])
	if err != nil {
		n.log.WarnContext(ctx, "Failed to apply block state transition", logger.Error(err))
		return
	}

	if err := n.sendCertificationRequest(ctx, n.peer.ID().String(), stateSummary); err != nil {
		n.log.WarnContext(ctx, "Failed to send certification request", logger.Error(err))
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
}

// handleMonitoring - monitors root communication, if for no UC is
// received for a long time then try and request one from root
func (n *Node) handleMonitoring(ctx context.Context, lastUCReceived, lastBlockReceived time.Time) {
	// check if we have not heard from root validator for T2 timeout + 1 sec
	// a new repeat UC must have been made by now (assuming root is fine) try and get it from other root nodes
	if time.Since(lastUCReceived) > n.shardConf.Load().T2Timeout+time.Second {
		// query latest UC from root
		n.sendHandshake(ctx)
	}
	// handle ledger replication timeout - no response from node is received
	if n.status.Load() == recovering && time.Since(n.lastLedgerReqTime) > n.conf.replicationConfig.timeout {
		n.log.WarnContext(ctx, "Ledger replication timeout, repeat request")
		n.sendLedgerReplicationRequest(ctx)
	}
}

func (n *Node) sendLedgerReplicationResponse(ctx context.Context, msg *replication.LedgerReplicationResponse, toId string) error {
	n.log.DebugContext(ctx, fmt.Sprintf("Sending ledger replication response '%s' to %s: %s", msg.UUID.String(), toId, msg.Pretty()))
	recoveringNodeID, err := peer.Decode(toId)
	if err != nil {
		return fmt.Errorf("decoding peer id %q: %w", toId, err)
	}

	if err = n.network.Send(ctx, msg, recoveringNodeID); err != nil {
		return fmt.Errorf("sending replication response: %w", err)
	}
	return nil
}

func (n *Node) handleLedgerReplicationRequest(ctx context.Context, lr *replication.LedgerReplicationRequest) error {
	n.log.DebugContext(ctx, fmt.Sprintf("Handling ledger replication request '%s' from '%s', starting block %d", lr.UUID.String(), lr.NodeID, lr.BeginBlockNumber))
	if err := lr.IsValid(); err != nil {
		// for now do not respond to obviously invalid requests
		return fmt.Errorf("invalid request, %w", err)
	}
	if lr.PartitionID != n.PartitionID() || !lr.ShardID.Equal(n.ShardID()) {
		resp := &replication.LedgerReplicationResponse{
			UUID:    lr.UUID,
			Status:  replication.WrongShard,
			Message: fmt.Sprintf("Wrong partition/shard: requested %s-%s, I'm %s-%s", lr.PartitionID, lr.ShardID, n.PartitionID(), n.ShardID()),
		}
		return n.sendLedgerReplicationResponse(ctx, resp, lr.NodeID)
	}
	startBlock := lr.BeginBlockNumber
	// the node has been started with a later state and does not have the needed data
	if startBlock <= n.fuc.GetRoundNumber() {
		resp := &replication.LedgerReplicationResponse{
			UUID:    lr.UUID,
			Status:  replication.BlocksNotFound,
			Message: fmt.Sprintf("Node does not have block: %v, first block: %v", startBlock, n.fuc.GetRoundNumber()+1),
		}
		return n.sendLedgerReplicationResponse(ctx, resp, lr.NodeID)
	}
	// the node is behind and does not have the needed data
	latestBlock := n.committedUC().GetRoundNumber()
	if latestBlock < startBlock {
		resp := &replication.LedgerReplicationResponse{
			UUID:    lr.UUID,
			Status:  replication.BlocksNotFound,
			Message: fmt.Sprintf("Node does not have block: %v, latest block: %v", startBlock, latestBlock),
		}
		return n.sendLedgerReplicationResponse(ctx, resp, lr.NodeID)
	}
	n.log.DebugContext(ctx, fmt.Sprintf("Preparing replication response from block %d", startBlock))
	go func() {
		blocks := make([]*types.Block, 0)
		blockCnt := uint64(0)
		dbIt := n.blockStore.Find(util.Uint64ToBytes(startBlock))
		defer func() {
			if err := dbIt.Close(); err != nil {
				n.log.WarnContext(ctx, "closing DB iterator", logger.Error(err))
			}
		}()
		var firstFetchedBlockNumber uint64
		var lastFetchedBlockNumber uint64
		var lastFetchedBlock *types.Block
		for ; dbIt.Valid(); dbIt.Next() {
			var bl types.Block
			roundNo := util.BytesToUint64(dbIt.Key())
			if err := dbIt.Value(&bl); err != nil {
				n.log.WarnContext(ctx, fmt.Sprintf("Ledger replication reply incomplete, failed to read block %d", roundNo), logger.Error(err))
				break
			}
			lastFetchedBlock = &bl
			if firstFetchedBlockNumber == 0 {
				firstFetchedBlockNumber = roundNo
			}
			lastFetchedBlockNumber = roundNo
			blocks = append(blocks, lastFetchedBlock)
			blockCnt++
			if blockCnt >= n.conf.replicationConfig.maxReturnBlocks ||
				(roundNo >= lr.EndBlockNumber && lr.EndBlockNumber > 0) {
				break
			}
		}
		resp := &replication.LedgerReplicationResponse{
			UUID:             lr.UUID,
			Status:           replication.Ok,
			Blocks:           blocks,
			FirstBlockNumber: firstFetchedBlockNumber,
			LastBlockNumber:  lastFetchedBlockNumber,
		}
		if err := n.sendLedgerReplicationResponse(ctx, resp, lr.NodeID); err != nil {
			n.log.WarnContext(ctx, fmt.Sprintf("Problem sending ledger replication response, %s", resp.Pretty()), logger.Error(err))
		}
	}()
	return nil
}

// handleLedgerReplicationResponse handles ledger replication responses from other partition nodes.
// This method is an approximation of YellowPaper algorithm 10 "Partition Node Recovery" (synchronous algorithm)
func (n *Node) handleLedgerReplicationResponse(ctx context.Context, lr *replication.LedgerReplicationResponse) error {
	if err := lr.IsValid(); err != nil {
		return fmt.Errorf("invalid ledger replication response, %w", err)
	}
	if n.status.Load() != recovering {
		n.log.DebugContext(ctx, fmt.Sprintf("Stale Ledger Replication response, node is not recovering: %s", lr.Pretty()))
		return nil
	}
	n.log.DebugContext(ctx, fmt.Sprintf("Ledger replication response '%s' received: %s, ", lr.UUID.String(), lr.Pretty()))
	if lr.Status != replication.Ok {
		// In case recovery was caused by a timeout, we can return to normal mode as long as we have all known blocks
		if n.isRecoveryComplete() {
			n.stopRecovery(ctx)
		}
		return fmt.Errorf("received error response, status=%s, message='%s'", lr.Status.String(), lr.Message)
	}

	// check for duplicate requests:
	// if we have already seen the first block in the replication response then the replication must have timed out and
	// multiple replication requests must have been performed, discard the last arrived duplicate batch
	lastCommittedRoundNumber := n.committedUC().GetRoundNumber()
	if lr.FirstBlockNumber <= lastCommittedRoundNumber {
		n.log.DebugContext(ctx, fmt.Sprintf("Duplicate Ledger Replication response, received blocks %d to %d but have latest committed block %d (replication timed out and node sent multiple replication requests?): %s", lr.FirstBlockNumber, lr.LastBlockNumber, lastCommittedRoundNumber, lr.Pretty()))
		return nil
	}

	for _, b := range lr.Blocks {
		if err := n.handleBlock(ctx, b); err != nil {
			return err
		}
	}

	if !n.isRecoveryComplete() {
		n.log.DebugContext(ctx, fmt.Sprintf("Recovery incomplete, committed block %d vs available block %d",
			n.committedUC().GetRoundNumber(), n.luc.Load().GetRoundNumber()))
		n.sendLedgerReplicationRequest(ctx)
		return nil
	}

	n.stopRecovery(ctx)

	if err := n.startNewRound(ctx); err != nil {
		return err
	}

	// try to apply the last received block proposal received during recovery,
	// it may fail if the block was finalized and is in fact the last block received
	if n.recoveryLastProp != nil {
		// try to apply it to the latest state, may fail
		if err := n.handleBlockProposal(ctx, n.recoveryLastProp); err != nil {
			n.log.DebugContext(ctx, "Recovery completed, failed to apply last received block proposal(stale?)", logger.Error(err))
		}
		n.recoveryLastProp = nil
	}

	return nil
}

func (n *Node) handleBlock(ctx context.Context, b *types.Block) error {
	committedUC := n.committedUC()
	blockUC, err := getUCv1(b)
	if err != nil {
		return fmt.Errorf("failed to extract UC from block: %w", err)
	}
	algo := n.conf.hashAlgorithm
	// Let's not verify shardConfHash inside the UC of Block, we only process
	// historical blocks from blockStore or from recovery, or as a non-validator.
	if err := b.IsValid(algo, nil); err != nil {
		// sends invalid blocks, do not trust the response and try again
		return fmt.Errorf("invalid block for round %v: %w", blockUC.GetRoundNumber(), err)
	}

	// LUC is the latest UC we have seen, it's ok to update it as soon as we see it.
	// TechnicalRecord not available, we might have a wrong idea of the current round/epoch.
	if err := n.updateLUC(ctx, blockUC, nil); err != nil {
		return fmt.Errorf("failed to update LUC: %w", err)
	}

	// it could be that we receive blocks from earlier time or later time, make sure to extend from what is missing
	if blockUC.GetRoundNumber() <= committedUC.GetRoundNumber() {
		n.log.DebugContext(ctx, fmt.Sprintf("latest committed block %v, skipping block %v", committedUC.GetRoundNumber(), blockUC.GetRoundNumber()))
		return nil
	} else if !blockUC.IsSuccessor(committedUC) {
		// No point in starting recovery during initialization - node won't start. Perhaps it should?
		if n.status.Load() != initializing {
			n.startRecovery(ctx)
		}
		return fmt.Errorf("missing blocks between rounds %v and %v", committedUC.GetRoundNumber(), blockUC.GetRoundNumber())
	}

	if !bytes.Equal(b.Header.PreviousBlockHash, committedUC.GetBlockHash()) {
		return fmt.Errorf("invalid block %v (expected previous block hash='%X', actual previous block hash='%X', )",
			blockUC.GetRoundNumber(), b.Header.PreviousBlockHash, committedUC.GetBlockHash())
	}

	n.log.DebugContext(ctx, fmt.Sprintf("Applying block from round %d", blockUC.GetRoundNumber()))

	// make sure it extends current state
	var state *txsystem.StateSummary
	state, err = n.transactionSystem.StateSummary()
	if err != nil {
		return fmt.Errorf("error reading current state, %w", err)
	}
	// Block must extend current state unless it's applied on uncertified genesis state
	if committedUC != nil && !bytes.Equal(blockUC.InputRecord.PreviousHash, state.Root()) {
		return fmt.Errorf("block does not extend current state, expected state hash: %X, actual state hash: %X",
			blockUC.InputRecord.PreviousHash, state.Root())
	}

	if err = verifyTxSystemState(state, blockUC.InputRecord); err != nil {
		n.revertState()
		return fmt.Errorf("failed to verify block %v state: %w", blockUC.GetRoundNumber(), err)
	}

	if err = n.finalizeBlock(ctx, b, blockUC); err != nil {
		// TODO: Should we revert in case only indexing failed?
		n.revertState()
		return fmt.Errorf("failed to finalize block %v: %w", blockUC.GetRoundNumber(), err)
	}
	return nil
}

func (n *Node) sendLedgerReplicationRequest(ctx context.Context) {
	startingBlockNr := n.committedUC().GetRoundNumber() + 1

	req := &replication.LedgerReplicationRequest{
		UUID:             uuid.New(),
		PartitionID:      n.PartitionID(),
		ShardID:          n.ShardID(),
		NodeID:           n.peer.ID().String(),
		BeginBlockNumber: startingBlockNr,
		EndBlockNumber:   startingBlockNr + n.conf.replicationConfig.maxFetchBlocks,
	}
	n.log.Log(ctx, logger.LevelTrace, "sending ledger replication request", logger.Data(req))

	// TODO: should send to non-validators also
	peers := n.Validators()
	if len(peers) == 0 {
		n.log.WarnContext(ctx, "Error sending ledger replication request, no peers")
		return
	}

	// send Ledger Replication request to a first alive randomly chosen node
	for _, p := range util.ShuffleSliceCopy(peers) {
		if n.peer.ID() == p {
			continue
		}
		n.log.DebugContext(ctx, fmt.Sprintf("Sending ledger replication request '%s' to %v", req.UUID.String(), p))
		// break loop on successful send, otherwise try again but different node, until all either
		// able to send or all attempts have failed
		if err := n.network.Send(ctx, req, p); err != nil {
			n.log.DebugContext(ctx, "Error sending ledger replication request", logger.Error(err))
			continue
		}
		// remember last request sent for timeout handling - if no response is received
		n.lastLedgerReqTime = time.Now()
		return
	}

	n.log.WarnContext(ctx, "failed to send ledger replication request (no peers, all peers down?)")
}

func (n *Node) sendBlockProposal(ctx context.Context) error {
	ltr := n.ltr.Load()
	if ltr == nil {
		// Should not reach here, leader is unknown without LTR
		return fmt.Errorf("missing LTR")
	}

	nodeID := n.peer.ID()
	prop := &blockproposal.BlockProposal{
		PartitionID:        n.PartitionID(),
		ShardID:            n.ShardID(),
		NodeID:             nodeID,
		UnicityCertificate: n.luc.Load(),
		Technical:          *ltr,
	}
	n.log.Log(ctx, logger.LevelTrace, "created BlockProposal", logger.Data(prop))
	if err := prop.Sign(n.conf.hashAlgorithm, n.conf.signer); err != nil {
		return fmt.Errorf("block proposal sign failed, %w", err)
	}
	return n.network.Send(ctx, prop, n.FilterValidatorNodes(nodeID)...)
}

func (n *Node) persistBlockProposal(pr *types.Block) error {
	if err := n.blockStore.Write(util.Uint32ToBytes(proposalKey), pr); err != nil {
		return fmt.Errorf("persist error, %w", err)
	}
	return nil
}

func (n *Node) sendCertificationRequest(ctx context.Context, blockAuthor string, state *txsystem.StateSummary) error {
	luc := n.luc.Load()
	uc := &types.UnicityCertificate{
		Version: 1,
		InputRecord: &types.InputRecord{
			Version:         1,
			RoundNumber:     n.currentRoundNumber(),
			Epoch:           n.currentEpoch(),
			PreviousHash:    luc.GetStateHash(),
			Hash:            state.Root(),
			SummaryValue:    state.SummaryValue(),
			Timestamp:       luc.UnicitySeal.Timestamp,
			BlockHash:       nil, // calculated below, nil if state hash does not change
			SumOfEarnedFees: state.SumOfEarnedFees(),
			ETHash:          state.ETHash(),
		},
	}
	ucBytes, err := types.Cbor.Marshal(uc)
	if err != nil {
		return fmt.Errorf("failed to marshal unicity certificate: %w", err)
	}

	pendingProposal := &types.Block{
		Header: &types.Header{
			Version:           1,
			PartitionID:       n.PartitionID(),
			ShardID:           n.ShardID(),
			ProposerID:        blockAuthor,
			PreviousBlockHash: n.committedUC().GetBlockHash(),
		},
		UnicityCertificate: ucBytes,
	}
	ir, err := pendingProposal.CalculateBlockHash(n.conf.hashAlgorithm)
	if err != nil {
		return fmt.Errorf("calculating block hash: %w", err)
	}
	if err = n.persistBlockProposal(pendingProposal); err != nil {
		n.transactionSystem.Revert()
		return fmt.Errorf("failed to store pending block proposal: %w", err)
	}
	n.pendingBlockProposal = pendingProposal

	// send new input record for certification
	req := &certification.BlockCertificationRequest{
		PartitionID: n.PartitionID(),
		ShardID:     n.ShardID(),
		NodeID:      n.peer.ID().String(),
		InputRecord: ir,
		StateSize:   0, // TODO leave empty for FGP?
	}

	if req.BlockSize, err = pendingProposal.Size(); err != nil {
		return fmt.Errorf("calculating block size: %w", err)
	}

	if err = req.Sign(n.conf.signer); err != nil {
		return fmt.Errorf("failed to sign certification request: %w", err)
	}
	n.log.InfoContext(ctx, fmt.Sprintf("Round %v sending block certification request to root chain, IR hash %X, Block Hash %X",
		uc.GetRoundNumber(), ir.Hash, ir.BlockHash))
	n.log.Log(ctx, logger.LevelTrace, "Block Certification req", logger.Data(req))

	rootValidators, err := n.RootValidators()
	if err != nil {
		return fmt.Errorf("failed to get current root validators: %w", err)
	}

	rootIDs, err := rootNodesSelector(luc, rootValidators, defaultNofRootNodes)
	if err != nil {
		return fmt.Errorf("selecting root nodes: %w", err)
	}
	return n.network.Send(ctx, req, rootIDs...)
}

func (n *Node) resetProposal() {
	n.pendingBlockProposal = nil
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
	rootEpoch := n.luc.Load().GetRootEpoch()
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
