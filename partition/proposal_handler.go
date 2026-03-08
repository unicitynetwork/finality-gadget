package partition

import (
	"bytes"
	"context"
	"fmt"

	"github.com/unicitynetwork/finality-gadget/network/protocol/blockproposal"
)

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
	if n.state.status == recovering {
		// but remember last block proposal received
		n.state.recoveryLastProp = prop
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
	luc := n.latestUC()

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
	expectedLeader := n.state.leader
	if expectedLeader == "" || prop.NodeID != expectedLeader {
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
