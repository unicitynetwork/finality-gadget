package txsystem

import (
	"errors"

	"github.com/unicitynetwork/bft-go-base/types"
)

var ErrStateContainsUncommittedChanges = errors.New("state contains uncommitted changes")

type (
	// TransactionSystem is a set of rules and logic for performing state transitions.
	// For FGP, it tracks the latest PoW hash and increments the state root.
	// The following sequence of methods is executed for each block: ApplyBlock and
	// Commit (consensus round was successful) or Revert (consensus round was unsuccessful).
	TransactionSystem interface {
		// StateSummary returns the summary of the current state.
		StateSummary() (*StateSummary, error)

		// ApplyBlock processes the FGP block data (the PoW hash) for the given round,
		// updates the temporary state, and returns the new StateSummary.
		ApplyBlock(round uint64, powHash []byte) (*StateSummary, error)

		// Revert signals the unsuccessful consensus round. When called the transaction system must revert all the changes
		// made during the ApplyBlock method call.
		Revert()

		// Commit signals the successful consensus round. Called after the block was approved by the root chain. When called
		// the transaction system must commit all the changes made during the ApplyBlock method call.
		Commit(uc *types.UnicityCertificate) error

		// CommittedUC returns the unicity certificate of the latest commit.
		CommittedUC() *types.UnicityCertificate
	}

	// StateSummary represents aggregate state hashes of the transaction system.
	StateSummary struct {
		rootHash        []byte
		summaryValue    []byte
		sumOfEarnedFees uint64
		etHash          []byte
	}
)

func NewStateSummary(rootHash []byte, summaryValue []byte, sumOfEarnedFees uint64, etHash []byte) *StateSummary {
	return &StateSummary{
		rootHash:        rootHash,
		summaryValue:    summaryValue,
		sumOfEarnedFees: sumOfEarnedFees,
		etHash:          etHash,
	}
}

func (s StateSummary) Root() []byte {
	return s.rootHash
}

func (s StateSummary) SummaryValue() []byte {
	return s.summaryValue
}

func (s StateSummary) SumOfEarnedFees() uint64 {
	return s.sumOfEarnedFees
}

func (s StateSummary) ETHash() []byte {
	return s.etHash
}
