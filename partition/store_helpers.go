package partition

import (
	"context"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/finality-gadget/logger"
)

// Key 0 is used for proposal, that way it is still possible to reverse iterate the DB
// and use 4 byte key, make it incompatible with block number
const proposalKey = uint32(0)

// storeBlock persists the block to the key-value store.
func (n *Node) storeBlock(roundNo []byte, b *types.Block) error {
	return n.blockStore.Write(roundNo, b)
}

// deleteBlock removes the block from the key-value store.
func (n *Node) deleteBlock(roundNo []byte) error {
	return n.blockStore.Delete(roundNo)
}

// storePendingProposal saves the pending block proposal to the database using the proposalKey.
func (n *Node) storePendingProposal(pr *types.Block) error {
	if err := n.blockStore.Write(util.Uint32ToBytes(proposalKey), pr); err != nil {
		return fmt.Errorf("persist error, %w", err)
	}
	return nil
}

// deletePendingProposal removes the pending proposal from the database.
func (n *Node) deletePendingProposal(ctx context.Context) {
	if err := n.blockStore.Delete(util.Uint32ToBytes(proposalKey)); err != nil {
		n.log.DebugContext(ctx, "DB proposal delete failed", logger.Error(err))
	}
}

// resetProposal sets the pending block proposal in memory to nil.
func (n *Node) resetProposal() {
	n.state.pendingBlockProposal = nil
}

// loadPendingProposal reads the pending block proposal from the database.
func (n *Node) loadPendingProposal() (*types.Block, bool, error) {
	pr := &types.Block{}
	found, err := n.blockStore.Read(util.Uint32ToBytes(proposalKey), pr)
	if err != nil {
		return nil, false, err
	}
	return pr, found, nil
}
