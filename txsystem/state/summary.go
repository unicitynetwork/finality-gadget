package state

import (
	"errors"
)

var ErrStateContainsUncommittedChanges = errors.New("state contains uncommitted changes")

// Summary represents aggregate state hashes of the transaction system.
type Summary struct {
	rootHash        []byte
	summaryValue    []byte
	sumOfEarnedFees uint64
	etHash          []byte
}

func NewStateSummary(rootHash []byte, summaryValue []byte, sumOfEarnedFees uint64, etHash []byte) *Summary {
	return &Summary{
		rootHash:        rootHash,
		summaryValue:    summaryValue,
		sumOfEarnedFees: sumOfEarnedFees,
		etHash:          etHash,
	}
}

func (s Summary) Root() []byte {
	return s.rootHash
}

func (s Summary) SummaryValue() []byte {
	return s.summaryValue
}

func (s Summary) SumOfEarnedFees() uint64 {
	return s.sumOfEarnedFees
}

func (s Summary) ETHash() []byte {
	return s.etHash
}
