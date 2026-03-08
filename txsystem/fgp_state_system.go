package txsystem

import (
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/finality-gadget/txsystem/state"
)

// var _ partition.TransactionSystem = (*FGPStateSystem)(nil)

type FGPStateSystem struct {
	mu sync.RWMutex

	shardConf          types.PartitionDescriptionRecord
	committedStateHash []byte
	pendingStateHash   []byte
	committedUC        *types.UnicityCertificate
	summaryValue       []byte
	sumOfEarnedFees    uint64
	etHash             []byte
}

func NewFGPStateSystem(shardConf types.PartitionDescriptionRecord) *FGPStateSystem {
	h := sha256.Sum256(nil) // TODO genesis state hash can be anything?
	return &FGPStateSystem{
		shardConf:          shardConf,
		committedStateHash: h[:],
		summaryValue:       []byte{}, // always empty non-nil constant for FGP, nil is not allowed by the BFT nodes
		sumOfEarnedFees:    0,        // always 0 for FGP
		etHash:             nil,      // always nil for FGP
	}
}

func (s *FGPStateSystem) StateSummary() (*state.Summary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.pendingStateHash != nil {
		return nil, state.ErrStateContainsUncommittedChanges
	}

	return state.NewStateSummary(s.committedStateHash, []byte{}, s.sumOfEarnedFees, s.etHash), nil
}

func (s *FGPStateSystem) ApplyBlock(round uint64, powHash []byte) (*state.Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pendingStateHash = powHash

	return state.NewStateSummary(s.pendingStateHash, s.summaryValue, s.sumOfEarnedFees, s.etHash), nil
}

func (s *FGPStateSystem) Revert() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pendingStateHash = nil
}

func (s *FGPStateSystem) Commit(uc *types.UnicityCertificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pendingStateHash == nil {
		return errors.New("no pending state to commit")
	}

	s.committedStateHash = s.pendingStateHash
	s.committedUC = uc
	s.pendingStateHash = nil

	return nil
}

func (s *FGPStateSystem) CommittedUC() *types.UnicityCertificate {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.committedUC
}
