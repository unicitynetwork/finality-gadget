package partition

import (
	"context"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/finality-gadget/logger"
	"github.com/unicitynetwork/finality-gadget/network/protocol/blockproposal"
	"github.com/unicitynetwork/finality-gadget/network/protocol/certification"
	"github.com/unicitynetwork/finality-gadget/txsystem/state"
)

func (n *Node) sendBlockProposal(ctx context.Context) error {
	ltr := n.latestTR()
	if ltr == nil {
		// Should not reach here, leader is unknown without LTR
		return fmt.Errorf("missing LTR")
	}

	nodeID := n.peer.ID()
	prop := &blockproposal.BlockProposal{
		PartitionID:        n.PartitionID(),
		ShardID:            n.ShardID(),
		NodeID:             nodeID,
		UnicityCertificate: n.latestUC(),
		Technical:          *ltr,
	}
	n.log.Log(ctx, logger.LevelTrace, "created BlockProposal", logger.Data(prop))
	if err := prop.Sign(n.conf.hashAlgorithm, n.conf.signer); err != nil {
		return fmt.Errorf("block proposal sign failed, %w", err)
	}
	return n.network.Send(ctx, prop, n.FilterValidatorNodes(nodeID)...)
}

func (n *Node) sendCertificationRequest(ctx context.Context, blockAuthor string, state *state.Summary) error {
	luc := n.latestUC()
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
	if err = n.storePendingProposal(pendingProposal); err != nil {
		n.transactionSystem.Revert()
		return fmt.Errorf("failed to store pending block proposal: %w", err)
	}
	n.state.pendingBlockProposal = pendingProposal

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
