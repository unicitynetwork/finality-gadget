package partition

import (
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/finality-gadget/network/protocol/blockproposal"
	"github.com/unicitynetwork/finality-gadget/network/protocol/certification"
)

type ConsensusState struct {
	status status

	// First UC for this node. The node is guaranteed to have blocks starting at fuc+1.
	// If node is started from genesis, then fuc remains nil (round == 0).
	fuc *types.UnicityCertificate

	// Latest UC this node has seen. Can be ahead of the committed UC during recovery.
	luc *types.UnicityCertificate

	// TR corresponding to the latest UC this node has seen (as referenced by luc.TRHash).
	// Can be nil if latest UC was received with a block (recovery or block propagation protocols).
	ltr *certification.TechnicalRecord

	leader               peer.ID
	pendingBlockProposal *types.Block
	recoveryLastProp     *blockproposal.BlockProposal
}
