package partition

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

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
		if n.state.status != initializing {
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
	state, err := n.transactionSystem.StateSummary()
	if err != nil {
		return fmt.Errorf("error reading current state, %w", err)
	}
	// Block must extend current state unless it's applied on uncertified genesis state
	if committedUC != nil && !bytes.Equal(blockUC.InputRecord.PreviousHash, state.Root()) {
		return fmt.Errorf("block does not extend current state, expected state hash: %X, actual state hash: %X",
			blockUC.InputRecord.PreviousHash, state.Root())
	}

	if err = state.EqualsIR(blockUC.InputRecord); err != nil {
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
