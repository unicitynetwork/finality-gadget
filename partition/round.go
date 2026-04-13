package partition

import (
	"context"
	"time"

	"github.com/unicitynetwork/finality-gadget/logger"
)

func (n *Node) startNewRound(ctx context.Context) error {
	n.resetProposal()

	// not a fatal issue, but log anyway
	n.deletePendingProposal(ctx)
	return nil
}

func (n *Node) ensureT1TimerState(ctx context.Context) {
	isLeader := n.state.leader == n.peer.ID()
	shouldBeRunning := isLeader && n.state.status != recovering
	isRunning := n.timer.isRunning.Load()

	if shouldBeRunning && !isRunning {
		n.startT1Timer(ctx)
	} else if !shouldBeRunning && isRunning {
		n.stopT1Timer()
	}
}

func (n *Node) stopT1Timer() {
	if n.timer.cancel != nil {
		n.timer.cancel()
		n.timer.cancel = nil
	}
	n.timer.isRunning.Store(false)
}

func (n *Node) startT1Timer(ctx context.Context) {
	n.stopT1Timer()

	txCtx, txCancel := context.WithCancel(ctx)
	n.timer.cancel = txCancel
	n.timer.isRunning.Store(true)

	go func() {
		select {
		case <-time.After(n.conf.t1Timeout):
			// Mark as not running so that ensureT1TimerState can restart the timer
			n.timer.isRunning.Store(false)

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
		n.transactionSystem.Revert()
		return
	}

	if err := n.sendCertificationRequest(ctx, n.peer.ID().String(), stateSummary); err != nil {
		n.log.WarnContext(ctx, "Failed to send certification request", logger.Error(err))
		n.transactionSystem.Revert()
		return
	}
}
