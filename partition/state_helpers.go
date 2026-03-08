package partition

import (
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/finality-gadget/network/protocol/certification"
)

func (n *Node) latestUC() *types.UnicityCertificate {
	return n.state.luc
}

func (n *Node) latestTR() *certification.TechnicalRecord {
	return n.state.ltr
}

func (n *Node) committedUC() *types.UnicityCertificate {
	return n.transactionSystem.CommittedUC()
}

func (n *Node) currentEpoch() uint64 {
	ltr := n.latestTR()
	if ltr != nil {
		return ltr.Epoch
	}

	// If we miss LTR then LUC is our best knowledge of current epoch
	luc := n.latestUC()
	if luc != nil {
		return luc.InputRecord.Epoch
	}

	return 0
}

func (n *Node) currentRoundNumber() uint64 {
	ltr := n.latestTR()
	if ltr != nil {
		return ltr.Round
	}
	// If we miss LTR then LUC is our best knowledge of current round
	return n.latestUC().GetRoundNumber() + 1
}
