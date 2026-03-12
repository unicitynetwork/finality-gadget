package state

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
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

func (s Summary) EqualsIR(ucIR *types.InputRecord) error {
	if ucIR == nil {
		return errors.New("unicity certificate input record is nil")
	}
	if !bytes.Equal(ucIR.Hash, s.rootHash) {
		return fmt.Errorf("transaction system state %X is not equal to unicity certificate value %X", s.rootHash, ucIR.Hash)
	}
	if !bytes.Equal(ucIR.SummaryValue, s.summaryValue) {
		return fmt.Errorf("transaction system summary value %X not equal to unicity certificate value %X", s.summaryValue, ucIR.SummaryValue)
	}
	if ucIR.SumOfEarnedFees != s.sumOfEarnedFees {
		return fmt.Errorf("transaction system sum of earned fees %d not equal to unicity certificate value %d", s.sumOfEarnedFees, ucIR.SumOfEarnedFees)
	}
	if !bytes.Equal(ucIR.ETHash, s.etHash) {
		return fmt.Errorf("transaction system executed transactions buffer hash '%X' not equal to unicity certificate value '%X'", s.etHash, ucIR.ETHash)
	}
	return nil
}
