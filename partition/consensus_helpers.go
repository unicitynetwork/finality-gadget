package partition

import (
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/finality-gadget/logger"
	"github.com/unicitynetwork/finality-gadget/network/protocol/handshake"
)

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

func (n *Node) revertState() {
	n.log.Warn("Reverting state")
	n.transactionSystem.Revert()
}

// finalizeBlock creates the block and adds it to the blockStore.
func (n *Node) finalizeBlock(ctx context.Context, b *types.Block, uc *types.UnicityCertificate) error {
	blockNumber := uc.GetRoundNumber()
	roundNoInBytes := util.Uint64ToBytes(blockNumber)
	isInitializing := n.state.status == initializing

	if !isInitializing {
		// persist the block _before_ committing to tx system
		// if write fails but the round is committed in tx system, there's no way back,
		// but if commit fails, we just remove the block from the store
		if err := n.storeBlock(roundNoInBytes, b); err != nil {
			return fmt.Errorf("db write failed, %w", err)
		}
	}

	if err := n.transactionSystem.Commit(uc); err != nil {
		err = fmt.Errorf("unable to finalize block %d: %w", blockNumber, err)

		if !isInitializing {
			if err2 := n.deleteBlock(roundNoInBytes); err2 != nil {
				err = errors.Join(err, fmt.Errorf("unable to delete block %d from store: %w", blockNumber, err2))
			}
		}
		return err
	}

	return nil
}
