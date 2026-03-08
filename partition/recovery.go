package partition

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	"github.com/unicitynetwork/finality-gadget/logger"
	"github.com/unicitynetwork/finality-gadget/network/protocol/replication"
)

func (n *Node) startRecovery(ctx context.Context) {
	if n.state.status == recovering {
		n.log.DebugContext(ctx, "Recovery already in progress")
		return
	}
	// starting recovery
	n.state.status = recovering
	n.revertState()
	n.resetProposal()

	fromBlockNr := n.committedUC().GetRoundNumber() + 1
	n.log.DebugContext(ctx, fmt.Sprintf("Entering recovery state, recover node from %d up to round %d",
		fromBlockNr, n.latestUC().GetRoundNumber()))
	n.sendLedgerReplicationRequest(ctx)
}

func (n *Node) stopRecovery(ctx context.Context) {
	committedBlock := n.committedUC().GetRoundNumber()
	n.log.InfoContext(ctx, fmt.Sprintf("Recovery complete, committed block %d", committedBlock))
	n.state.status = normal
}

func (n *Node) isRecoveryComplete() bool {
	return n.committedUC().GetRoundNumber() == n.latestUC().GetRoundNumber()
}

func (n *Node) sendLedgerReplicationRequest(ctx context.Context) {
	startingBlockNr := n.committedUC().GetRoundNumber() + 1

	req := &replication.LedgerReplicationRequest{
		UUID:             uuid.New(),
		PartitionID:      n.PartitionID(),
		ShardID:          n.ShardID(),
		NodeID:           n.peer.ID().String(),
		BeginBlockNumber: startingBlockNr,
		EndBlockNumber:   startingBlockNr + n.conf.replicationConfig.maxFetchBlocks,
	}
	n.log.Log(ctx, logger.LevelTrace, "sending ledger replication request", logger.Data(req))

	// TODO: should send to non-validators also
	peers := n.Validators()
	if len(peers) == 0 {
		n.log.WarnContext(ctx, "Error sending ledger replication request, no peers")
		return
	}

	// send Ledger Replication request to a first alive randomly chosen node
	for _, p := range util.ShuffleSliceCopy(peers) {
		if n.peer.ID() == p {
			continue
		}
		n.log.DebugContext(ctx, fmt.Sprintf("Sending ledger replication request '%s' to %v", req.UUID.String(), p))
		// break loop on successful send, otherwise try again but different node, until all either
		// able to send or all attempts have failed
		if err := n.network.Send(ctx, req, p); err != nil {
			n.log.DebugContext(ctx, "Error sending ledger replication request", logger.Error(err))
			continue
		}
		// remember last request sent for timeout handling - if no response is received
		n.lastLedgerReqTime = time.Now()
		return
	}

	n.log.WarnContext(ctx, "failed to send ledger replication request (no peers, all peers down?)")
}

func (n *Node) sendLedgerReplicationResponse(ctx context.Context, msg *replication.LedgerReplicationResponse, toId string) error {
	n.log.DebugContext(ctx, fmt.Sprintf("Sending ledger replication response '%s' to %s: %s", msg.UUID.String(), toId, msg.Pretty()))
	recoveringNodeID, err := peer.Decode(toId)
	if err != nil {
		return fmt.Errorf("decoding peer id %q: %w", toId, err)
	}

	if err = n.network.Send(ctx, msg, recoveringNodeID); err != nil {
		return fmt.Errorf("sending replication response: %w", err)
	}
	return nil
}

func (n *Node) handleLedgerReplicationRequest(ctx context.Context, lr *replication.LedgerReplicationRequest) error {
	n.log.DebugContext(ctx, fmt.Sprintf("Handling ledger replication request '%s' from '%s', starting block %d", lr.UUID.String(), lr.NodeID, lr.BeginBlockNumber))
	if err := lr.IsValid(); err != nil {
		// for now do not respond to obviously invalid requests
		return fmt.Errorf("invalid request, %w", err)
	}
	if lr.PartitionID != n.PartitionID() || !lr.ShardID.Equal(n.ShardID()) {
		resp := &replication.LedgerReplicationResponse{
			UUID:    lr.UUID,
			Status:  replication.WrongShard,
			Message: fmt.Sprintf("Wrong partition/shard: requested %s-%s, I'm %s-%s", lr.PartitionID, lr.ShardID, n.PartitionID(), n.ShardID()),
		}
		return n.sendLedgerReplicationResponse(ctx, resp, lr.NodeID)
	}
	startBlock := lr.BeginBlockNumber
	// the node has been started with a later state and does not have the needed data
	if startBlock <= n.state.fuc.GetRoundNumber() {
		resp := &replication.LedgerReplicationResponse{
			UUID:    lr.UUID,
			Status:  replication.BlocksNotFound,
			Message: fmt.Sprintf("Node does not have block: %v, first block: %v", startBlock, n.state.fuc.GetRoundNumber()+1),
		}
		return n.sendLedgerReplicationResponse(ctx, resp, lr.NodeID)
	}
	// the node is behind and does not have the needed data
	latestBlock := n.committedUC().GetRoundNumber()
	if latestBlock < startBlock {
		resp := &replication.LedgerReplicationResponse{
			UUID:    lr.UUID,
			Status:  replication.BlocksNotFound,
			Message: fmt.Sprintf("Node does not have block: %v, latest block: %v", startBlock, latestBlock),
		}
		return n.sendLedgerReplicationResponse(ctx, resp, lr.NodeID)
	}
	n.log.DebugContext(ctx, fmt.Sprintf("Preparing replication response from block %d", startBlock))
	go func() {
		blocks := make([]*types.Block, 0)
		blockCnt := uint64(0)
		dbIt := n.blockStore.Find(util.Uint64ToBytes(startBlock))
		defer func() {
			if err := dbIt.Close(); err != nil {
				n.log.WarnContext(ctx, "closing DB iterator", logger.Error(err))
			}
		}()
		var firstFetchedBlockNumber uint64
		var lastFetchedBlockNumber uint64
		var lastFetchedBlock *types.Block
		for ; dbIt.Valid(); dbIt.Next() {
			var bl types.Block
			roundNo := util.BytesToUint64(dbIt.Key())
			if err := dbIt.Value(&bl); err != nil {
				n.log.WarnContext(ctx, fmt.Sprintf("Ledger replication reply incomplete, failed to read block %d", roundNo), logger.Error(err))
				break
			}
			lastFetchedBlock = &bl
			if firstFetchedBlockNumber == 0 {
				firstFetchedBlockNumber = roundNo
			}
			lastFetchedBlockNumber = roundNo
			blocks = append(blocks, lastFetchedBlock)
			blockCnt++
			if blockCnt >= n.conf.replicationConfig.maxReturnBlocks ||
				(roundNo >= lr.EndBlockNumber && lr.EndBlockNumber > 0) {
				break
			}
		}
		resp := &replication.LedgerReplicationResponse{
			UUID:             lr.UUID,
			Status:           replication.Ok,
			Blocks:           blocks,
			FirstBlockNumber: firstFetchedBlockNumber,
			LastBlockNumber:  lastFetchedBlockNumber,
		}
		if err := n.sendLedgerReplicationResponse(ctx, resp, lr.NodeID); err != nil {
			n.log.WarnContext(ctx, fmt.Sprintf("Problem sending ledger replication response, %s", resp.Pretty()), logger.Error(err))
		}
	}()
	return nil
}

// handleLedgerReplicationResponse handles ledger replication responses from other partition nodes.
// This method is an approximation of YellowPaper algorithm 10 "Partition Node Recovery" (synchronous algorithm)
func (n *Node) handleLedgerReplicationResponse(ctx context.Context, lr *replication.LedgerReplicationResponse) error {
	if err := lr.IsValid(); err != nil {
		return fmt.Errorf("invalid ledger replication response, %w", err)
	}
	if n.state.status != recovering {
		n.log.DebugContext(ctx, fmt.Sprintf("Stale Ledger Replication response, node is not recovering: %s", lr.Pretty()))
		return nil
	}
	n.log.DebugContext(ctx, fmt.Sprintf("Ledger replication response '%s' received: %s, ", lr.UUID.String(), lr.Pretty()))
	if lr.Status != replication.Ok {
		// In case recovery was caused by a timeout, we can return to normal mode as long as we have all known blocks
		if n.isRecoveryComplete() {
			n.stopRecovery(ctx)
		}
		return fmt.Errorf("received error response, status=%s, message='%s'", lr.Status.String(), lr.Message)
	}

	// check for duplicate requests:
	// if we have already seen the first block in the replication response then the replication must have timed out and
	// multiple replication requests must have been performed, discard the last arrived duplicate batch
	lastCommittedRoundNumber := n.committedUC().GetRoundNumber()
	if lr.FirstBlockNumber <= lastCommittedRoundNumber {
		n.log.DebugContext(ctx, fmt.Sprintf("Duplicate Ledger Replication response, received blocks %d to %d but have latest committed block %d (replication timed out and node sent multiple replication requests?): %s", lr.FirstBlockNumber, lr.LastBlockNumber, lastCommittedRoundNumber, lr.Pretty()))
		return nil
	}

	for _, b := range lr.Blocks {
		if err := n.handleBlock(ctx, b); err != nil {
			return err
		}
	}

	if !n.isRecoveryComplete() {
		n.log.DebugContext(ctx, fmt.Sprintf("Recovery incomplete, committed block %d vs available block %d",
			n.committedUC().GetRoundNumber(), n.latestUC().GetRoundNumber()))
		n.sendLedgerReplicationRequest(ctx)
		return nil
	}

	n.stopRecovery(ctx)

	if err := n.startNewRound(ctx); err != nil {
		return err
	}

	// try to apply the last received block proposal received during recovery,
	// it may fail if the block was finalized and is in fact the last block received
	if n.state.recoveryLastProp != nil {
		// try to apply it to the latest state, may fail
		if err := n.handleBlockProposal(ctx, n.state.recoveryLastProp); err != nil {
			n.log.DebugContext(ctx, "Recovery completed, failed to apply last received block proposal(stale?)", logger.Error(err))
		}
		n.state.recoveryLastProp = nil
	}

	return nil
}
