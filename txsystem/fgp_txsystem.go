package txsystem

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	powtypes "github.com/unicitynetwork/finality-gadget/pow/types"
	"github.com/unicitynetwork/finality-gadget/txsystem/state"
)

type FGPTxSystem struct {
	mu sync.RWMutex

	log                  *slog.Logger
	shardConf            types.PartitionDescriptionRecord
	powClient            powtypes.Client
	genesisHash          []byte // genesis hash is nil
	dFG                  uint64 // number of PoW confirmations required for finalization
	committedStateHash   []byte // PoW block hash
	committedStateHeight uint64 // PoW block height
	pendingStateHash     []byte // pending PoW block hash
	pendingStateHeight   uint64 // pending PoW block height
	committedUC          *types.UnicityCertificate
	summaryValue         []byte
	sumOfEarnedFees      uint64
	etHash               []byte
}

func NewFGPTxSystem(shardConf types.PartitionDescriptionRecord, powClient powtypes.Client, log *slog.Logger) (*FGPTxSystem, error) {
	dFGString, found := shardConf.PartitionParams["dFG"]
	if !found {
		return nil, errors.New("dFG not defined in shard conf")
	}
	dFG, err := strconv.ParseUint(dFGString, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("non numeric dFG defined in shard conf: %w", err)
	}
	return &FGPTxSystem{
		log:                log,
		shardConf:          shardConf,
		powClient:          powClient,
		dFG:                dFG,
		committedStateHash: nil,
		genesisHash:        nil,      // initial UC hash is nil
		summaryValue:       []byte{}, // always empty non-nil constant for FGP, nil is not allowed by the BFT nodes
		sumOfEarnedFees:    0,        // always 0 for FGP
		etHash:             nil,      // always nil for FGP
	}, nil
}

func (s *FGPTxSystem) UpdateConfig(shardConf *types.PartitionDescriptionRecord) error {
	dFGString, found := shardConf.PartitionParams["dFG"]
	if !found {
		return errors.New("dFG not defined in shard conf")
	}
	dFG, err := strconv.ParseUint(dFGString, 10, 64)
	if err != nil {
		return fmt.Errorf("non numeric dFG defined in shard conf: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.shardConf = *shardConf
	s.dFG = dFG

	return nil
}

func (s *FGPTxSystem) StateSummary() (*state.Summary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.pendingStateHash != nil {
		return nil, state.ErrStateContainsUncommittedChanges
	}

	return state.NewStateSummary(s.committedStateHash, s.summaryValue, s.sumOfEarnedFees, s.etHash), nil
}

func (s *FGPTxSystem) LeaderPropose(ctx context.Context, round uint64) (*state.Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Example height calculation:
	// tipHeight=10
	// dFG=6 (defined as needing 6 confirmations)
	// the chain tip (latest block) is considered to have 1 confirmation
	// so the maximum allowed fork block height is tipHeight-dfg+1=5

	// 1. Get the current tip
	tip, err := s.powClient.GetTip(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get PoW chain tip: %w", err)
	}

	// 2. Find the height of the latest FG-certified PoW block (since we do not store them in blocks we have to query it)
	// if no certified blocks yet (genesis block) then set hFG=0
	var hFG uint64
	if !bytes.Equal(s.pendingStateHash, s.genesisHash) {
		hexHash := hex.EncodeToString(s.committedStateHash)
		lastCertBlock, err := s.powClient.GetBlockHeaderByHash(ctx, hexHash)
		if err != nil {
			return nil, fmt.Errorf("failed to find last certified block for hash '%s': %w", hexHash, err)
		}
		hFG = lastCertBlock.Height
	}

	// 3. Ensure we have a new PoW block to finalize
	if tip.Height <= hFG {
		return nil, fmt.Errorf("no new final enough PoW block: tip height %d, hFG %d", tip.Height, hFG)
	}

	// 4. Ensure the block is "final enough"
	if tip.Height-hFG < s.dFG-1 {
		return nil, fmt.Errorf("no new final enough PoW block: tip height %d, hFG %d, dFG %d (not enough confirmations)", tip.Height, hFG, s.dFG)
	}

	// 5. Get the candidate block at depth dFG from tip
	candidateHeight := tip.Height - (s.dFG - 1)
	if candidateHeight <= hFG {
		return nil, fmt.Errorf("no new final enough PoW block: candidate height %d <= hFG %d (already finalized or older)", candidateHeight, hFG)
	}

	candBlock, err := s.powClient.GetBlockHeaderByHeight(ctx, candidateHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to get candidate block at height %d: %w", candidateHeight, err)
	}

	// 6. ensure(no competing fork visible at Bcand.height)
	tips, err := s.powClient.GetChainTips(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain tips for fork check: %w", err)
	}

	for _, t := range tips {
		// active chain is the main chain, safe to skip
		if t.Status == "active" {
			continue
		}
		forkHeight := t.Height - t.BranchLen
		if t.Height >= candidateHeight && forkHeight < candidateHeight {
			return nil, fmt.Errorf("competing fork visible: branch at height %d diverged at %d", t.Height, forkHeight)
		}
	}

	candHashBytes, err := hex.DecodeString(candBlock.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode candidate block hash: %w", err)
	}

	s.pendingStateHash = candHashBytes
	s.pendingStateHeight = candBlock.Height

	return state.NewStateSummary(s.pendingStateHash, s.summaryValue, s.sumOfEarnedFees, s.etHash), nil
}

func (s *FGPTxSystem) FollowerVerify(ctx context.Context, round uint64, proposedRoot []byte) (*state.Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. If the proposed root matches our current state, it's a valid "no-op" transition.
	// This handles both the genesis bootstrap and staying at a previously certified block.
	if bytes.Equal(proposedRoot, s.committedStateHash) {
		s.pendingStateHash = proposedRoot
		s.pendingStateHeight = s.committedStateHeight
		return state.NewStateSummary(s.pendingStateHash, s.summaryValue, s.sumOfEarnedFees, s.etHash), nil
	}

	// 2. Get the block by hash
	hexHash := hex.EncodeToString(proposedRoot)
	block, err := s.powClient.GetBlockHeaderByHash(ctx, hexHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block by hash '%s': %w", hexHash, err)
	}

	if !block.IsActive() {
		return nil, fmt.Errorf("proposed block is not in the active chain")
	}

	// 3. Get the current tip
	tip, err := s.powClient.GetTip(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get PoW chain tip: %w", err)
	}

	// 4. Ensure the block has sufficient confirmations
	if tip.Height-block.Height < s.dFG-1 {
		return nil, fmt.Errorf("proposed block does not have sufficient confirmations (depth %d, required %d)", tip.Height-block.Height, s.dFG)
	}

	s.pendingStateHash = proposedRoot
	s.pendingStateHeight = block.Height

	return state.NewStateSummary(s.pendingStateHash, s.summaryValue, s.sumOfEarnedFees, s.etHash), nil
}

func (s *FGPTxSystem) RestoreState(ctx context.Context, uc *types.UnicityCertificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stateHash := uc.GetStateHash()

	// fetch committedStateHeight from PoW node since we don't store PoW height (currently only used for logging)
	if len(stateHash) > 0 {
		stateHashHex := hex.EncodeToString(stateHash)
		block, err := s.powClient.GetBlockHeaderByHash(ctx, stateHashHex)
		if err != nil {
			return fmt.Errorf("failed to get block by hash '%s': %w", stateHashHex, err)
		}
		s.committedStateHeight = block.Height
	}

	s.committedStateHash = stateHash
	s.committedUC = uc
	s.pendingStateHash = nil
	s.pendingStateHeight = 0

	return nil
}

func (s *FGPTxSystem) Revert() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pendingStateHash = nil
	s.pendingStateHeight = 0
}

func (s *FGPTxSystem) Commit(uc *types.UnicityCertificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !bytes.Equal(s.pendingStateHash, uc.GetStateHash()) {
		return fmt.Errorf("state mismatch: pending %X, certified %X", s.pendingStateHash, uc.GetStateHash())
	}

	if !bytes.Equal(s.pendingStateHash, s.committedStateHash) {
		s.log.Info("new PoW block certified",
			slog.Uint64("fgp_round", uc.GetRoundNumber()),
			slog.Uint64("bft_round", uc.GetRootRoundNumber()),
			slog.Uint64("pow_height", s.pendingStateHeight),
			slog.String("pow_hash", hex.EncodeToString(s.pendingStateHash)))
	}

	s.committedStateHash = s.pendingStateHash
	s.committedStateHeight = s.pendingStateHeight
	s.committedUC = uc
	s.pendingStateHash = nil
	s.pendingStateHeight = 0

	return nil
}

func (s *FGPTxSystem) CommittedUC() *types.UnicityCertificate {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.committedUC
}
