package partition

import (
	"bytes"
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/finality-gadget/logger"
	"github.com/unicitynetwork/finality-gadget/network/protocol/certification"
)

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
	prevLUC := n.latestUC()

	if err := n.updateLUC(ctx, uc, tr); err != nil {
		return fmt.Errorf("failed to update LUC: %w", err)
	}

	// We have a new or a duplicate luc, let's see what we should do.
	if n.state.status == recovering {
		// Doesn't really matter what we got, recovery will handle it.
		n.log.DebugContext(ctx, "Recovery already in progress")
		return nil
	}

	wasInitializing := n.state.status == initializing
	if wasInitializing {
		// First UC received after an initial handshake with a root node -> initialization finished.
		n.state.status = normal
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
	if n.state.pendingBlockProposal == nil {
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

	proposedIR, err := n.state.pendingBlockProposal.InputRecord()
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
	n.state.pendingBlockProposal.UnicityCertificate, err = types.Cbor.Marshal(uc)
	if err != nil {
		return fmt.Errorf("failed to marshal unicity certificate: %w", err)
	}
	// UC certifies pending block proposal
	if err := n.finalizeBlock(ctx, n.state.pendingBlockProposal, uc); err != nil {
		n.startRecovery(ctx)
		return fmt.Errorf("block %v finalize failed: %w", uc.GetRoundNumber(), err)
	}

	return n.startNewRound(ctx)
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

	luc := n.latestUC()
	if n.state.status == recovering && luc.GetRootRoundNumber() > uc.GetRootRoundNumber() {
		// During recovery, UC from a recovered block is usually older than the LUC.
		// Do not attempt to update LUC in that case.
		return nil
	}

	if n.state.status != initializing {
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

	if uc.IsDuplicate(luc) && n.latestTR() != nil {
		// It's OK to receive duplicates, just no need to update luc/ltr if we have both
		return nil
	}

	prevEpoch := n.currentEpoch()
	if tr != nil {
		leaderPeerID, err := peer.Decode(tr.Leader)
		if err != nil {
			return fmt.Errorf("decoding leader peerID from %q: %w", tr.Leader, err)
		}
		n.state.leader = leaderPeerID
		n.state.ltr = tr
		n.log.DebugContext(ctx, "updated LTR")
	} else {
		n.state.leader = ""
		n.state.ltr = nil
		n.log.DebugContext(ctx, "missing LTR")
	}

	n.state.luc = uc
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
