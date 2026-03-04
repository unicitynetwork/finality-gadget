package partition

import (
	gocrypto "crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/finality-gadget/network/protocol/blockproposal"
)

type (
	// UnicityCertificateValidator is used to validate certificates.UnicityCertificate.
	UnicityCertificateValidator interface {
		// Validate validates the given UC. Returns an error if UC is not valid.
		Validate(uc *types.UnicityCertificate, shardConf *types.PartitionDescriptionRecord, trustBase types.RootTrustBase) error
	}

	// BlockProposalValidator is used to validate block proposals.
	BlockProposalValidator interface {
		// Validate validates the given blockproposal.BlockProposal. Returns an error if given block proposal
		// is not valid.
		Validate(bp *blockproposal.BlockProposal, shardConf *types.PartitionDescriptionRecord, trustBase types.RootTrustBase) error
	}

	// DefaultUnicityCertificateValidator is a default implementation of UnicityCertificateValidator.
	DefaultUnicityCertificateValidator struct {
		hashAlg gocrypto.Hash
	}

	// DefaultBlockProposalValidator is a default implementation of UnicityCertificateValidator.
	DefaultBlockProposalValidator struct {
		hashAlg gocrypto.Hash
	}
)

// NewDefaultUnicityCertificateValidator creates a new instance of default UnicityCertificateValidator.
func NewDefaultUnicityCertificateValidator(hashAlg gocrypto.Hash) UnicityCertificateValidator {
	return &DefaultUnicityCertificateValidator{hashAlg: hashAlg}
}

func (ucv *DefaultUnicityCertificateValidator) Validate(uc *types.UnicityCertificate, shardConf *types.PartitionDescriptionRecord, trustBase types.RootTrustBase) error {
	if shardConf == nil {
		return errors.New("shard conf is nil")
	}

	var shardConfHash []byte
	// Only verify shardConfHash if UC epoch matches the current shard epoch.
	if uc != nil && uc.GetShardEpoch() == shardConf.Epoch {
		var err error
		shardConfHash, err = shardConf.Hash(ucv.hashAlg)
		if err != nil {
			return fmt.Errorf("failed to calculate shard conf hash: %w", err)
		}
	}
	return uc.Verify(trustBase, ucv.hashAlg, shardConf.PartitionID, shardConf.ShardID, shardConfHash)
}

// NewDefaultBlockProposalValidator creates a new instance of default BlockProposalValidator.
func NewDefaultBlockProposalValidator(hashAlg gocrypto.Hash) BlockProposalValidator {
	return &DefaultBlockProposalValidator{hashAlg: hashAlg}
}

func (bpv *DefaultBlockProposalValidator) Validate(bp *blockproposal.BlockProposal, shardConf *types.PartitionDescriptionRecord, trustBase types.RootTrustBase) error {
	return bp.IsValid(trustBase, shardConf, bpv.hashAlg)
}
