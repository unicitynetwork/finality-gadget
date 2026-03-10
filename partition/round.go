package partition

import (
	"context"
	"time"

	"github.com/unicitynetwork/finality-gadget/logger"
)

func (n *Node) startNewRound(ctx context.Context) error {
	n.resetProposal()
	n.startT1Timer(ctx)

	// not a fatal issue, but log anyway
	n.deletePendingProposal(ctx)
	return nil
}

func (n *Node) startT1Timer(ctx context.Context) {
	// stop existing timer
	if stopFunc, ok := n.timer.stop.Load().(func()); ok && stopFunc != nil {
		stopFunc()
	}

	txCtx, txCancel := context.WithCancel(ctx)
	n.timer.stop.Store(func() { txCancel() })

	go func() {
		select {
		case <-time.After(n.conf.t1Timeout):
			// Rather than call handleT1TimeoutEvent directly send signal to main
			// loop - helps to avoid concurrency issues with (repeat) UC handling.
			select {
			case n.timer.event <- struct{}{}:
			case <-txCtx.Done():
			}
		case <-txCtx.Done():
		}
	}()
}

func (n *Node) handleT1TimeoutEvent(ctx context.Context) {
	if stopFunc, ok := n.timer.stop.Load().(func()); ok && stopFunc != nil {
		stopFunc()
	}
	n.timer.stop.Store(func() {})

	if n.state.status == recovering {
		n.log.InfoContext(ctx, "T1 timeout: node is recovering")
		return
	}
	n.log.DebugContext(ctx, "Handling T1 timeout")
	// if node is not leader, then do not do anything
	if n.state.leader != n.peer.ID() {
		n.log.DebugContext(ctx, "Current node is not the leader.")
		return
	}

	n.log.DebugContext(ctx, "Current node is the leader.")

	stateSummary, err := n.transactionSystem.LeaderPropose(ctx, n.currentRoundNumber())
	if err != nil {
		n.log.WarnContext(ctx, "Leader failed to apply block state transition", logger.Error(err))
		n.transactionSystem.Revert()
		return
	}

	if err := n.sendBlockProposal(ctx, stateSummary.Root()); err != nil {
		n.log.WarnContext(ctx, "Failed to send BlockProposal", logger.Error(err))
		return
	}

	if err := n.sendCertificationRequest(ctx, n.peer.ID().String(), stateSummary); err != nil {
		n.log.WarnContext(ctx, "Failed to send certification request", logger.Error(err))
	}
}
