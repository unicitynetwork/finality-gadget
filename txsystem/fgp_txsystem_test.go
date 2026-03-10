package txsystem

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/finality-gadget/internal/testutils/logger"
	powtypes "github.com/unicitynetwork/finality-gadget/pow/types"
)

func TestProposeBlock(t *testing.T) {
	log := logger.New(t)

	// dFG=6 in most tests
	// candidateHeight=tipHeight-dFG+1 (the height of the block FGP is considering finalizing)
	tests := []struct {
		name          string
		tipHeight     uint64
		tips          []powtypes.ChainTip
		expectedError string
	}{
		{
			name:      "No competing fork",
			tipHeight: 10, // candidateHeight = 10 - (6 - 1) = 5
			tips: []powtypes.ChainTip{
				{Status: "active", Height: 10, BranchLen: 0},
			},
			expectedError: "",
		},
		{
			name:      "Fork hasn't reached candidateHeight",
			tipHeight: 10, // candidateHeight = 5
			tips: []powtypes.ChainTip{
				{Status: "active", Height: 10, BranchLen: 0},
				// diverged at 3, reached 4
				{Status: "valid-fork", Height: 4, BranchLen: 1},
			},
			expectedError: "",
		},
		{
			name:      "Fork diverged before candidateHeight and reaches it",
			tipHeight: 10, // candidateHeight = 5
			tips: []powtypes.ChainTip{
				{Status: "active", Height: 10, BranchLen: 0},
				// diverged at 3, reached 6
				{Status: "valid-fork", Height: 6, BranchLen: 3},
			},
			expectedError: "competing fork visible: branch at height 6 diverged at 3",
		},
		{
			name:      "Fork tip exactly at candidateHeight",
			tipHeight: 10, // candidateHeight = 5
			tips: []powtypes.ChainTip{
				{Status: "active", Height: 10, BranchLen: 0},
				// diverged at 3, reached exactly 5
				{Status: "valid-fork", Height: 5, BranchLen: 2},
			},
			expectedError: "competing fork visible: branch at height 5 diverged at 3",
		},
		{
			name:      "Fork diverged exactly at candidateHeight",
			tipHeight: 10, // candidateHeight = 5
			tips: []powtypes.ChainTip{
				{Status: "active", Height: 10, BranchLen: 0},
				// diverged at 5, reached 7
				{Status: "valid-fork", Height: 7, BranchLen: 2},
			},
			expectedError: "",
		},
		{
			name:      "Fork diverged after candidateHeight",
			tipHeight: 10, // candidateHeight = 5
			tips: []powtypes.ChainTip{
				{Status: "active", Height: 10, BranchLen: 0},
				// diverged at 6, reached 8
				{Status: "valid-fork", Height: 8, BranchLen: 2},
			},
			expectedError: "",
		},
		{
			name:      "Invalid branch but reaches candidateHeight",
			tipHeight: 10, // candidateHeight = 5
			tips: []powtypes.ChainTip{
				{Status: "active", Height: 10, BranchLen: 0},
				// diverged at 3, reached 6
				{Status: "invalid", Height: 6, BranchLen: 3},
			},
			expectedError: "competing fork visible: branch at height 6 diverged at 3",
		},
		{
			name:      "Multiple forks, one competing",
			tipHeight: 11, // candidateHeight = 11 - (6 - 1) = 6
			tips: []powtypes.ChainTip{
				{Status: "active", Height: 11, BranchLen: 0},
				{Status: "valid-fork", Height: 7, BranchLen: 2}, // diverged at 5, reaches 7 (competes at 6)
				{Status: "valid-fork", Height: 9, BranchLen: 2}, // diverged at 7, safe
			},
			expectedError: "competing fork visible: branch at height 7 diverged at 5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockPowClient{
				tipHeight: tt.tipHeight,
				tips:      tt.tips,
			}
			partitionParams := map[string]string{
				"dFG": "6",
			}
			s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{PartitionParams: partitionParams}, mockClient, log)
			require.NoError(t, err)

			summary, err := s.LeaderPropose(t.Context(), 1)

			if tt.expectedError != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.expectedError)
				require.Nil(t, summary)
			} else {
				require.NoError(t, err)
				require.NotNil(t, summary)
				require.NotNil(t, summary.Root())
			}
		})
	}
}

func TestVerifyBlock(t *testing.T) {
	log := logger.New(t)

	tests := []struct {
		name          string
		tipHeight     uint64
		proposedHash  string
		mockBlock     *powtypes.BlockHeader
		expectedError string
	}{
		{
			name:         "Valid block in active chain with sufficient confirmations",
			tipHeight:    10,
			proposedHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			mockBlock: &powtypes.BlockHeader{
				Hash:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Height:        5, // depth = 10 - 5 = 5 (equals dFG - 1) -> 6 confirmations
				Confirmations: 6, // Active chain
			},
			expectedError: "",
		},
		{
			name:         "Valid block in active chain but NOT enough confirmations",
			tipHeight:    9,
			proposedHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			mockBlock: &powtypes.BlockHeader{
				Hash:          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Height:        5, // depth = 9 - 5 = 4 (< dFG - 1) -> 5 confirmations
				Confirmations: 5, // Active chain
			},
			expectedError: "proposed block does not have sufficient confirmations (depth 4, required 6)",
		},
		{
			name:         "Orphaned block (not in active chain)",
			tipHeight:    10,
			proposedHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			mockBlock: &powtypes.BlockHeader{
				Hash:          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				Height:        5,  // Height would have enough confirmations...
				Confirmations: -1, // But it's an orphaned fork!
			},
			expectedError: "proposed block is not in the active chain",
		},
		{
			name:          "Genesis block with empty hash",
			tipHeight:     10,
			proposedHash:  "",
			mockBlock:     nil, // powClient should not be called
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockPowClient{
				tipHeight: tt.tipHeight,
				blocks: map[string]*powtypes.BlockHeader{
					tt.proposedHash: tt.mockBlock,
				},
			}
			partitionParams := map[string]string{
				"dFG": "6",
			}
			s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{PartitionParams: partitionParams}, mockClient, log)
			require.NoError(t, err)

			hashBytes, _ := hex.DecodeString(tt.proposedHash)
			summary, err := s.FollowerVerify(context.Background(), 1, hashBytes)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, summary)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, summary)
				assert.Equal(t, hashBytes, summary.Root())
			}
		})
	}
}

func TestCommit(t *testing.T) {
	log := logger.New(t)
	partitionParams := map[string]string{"dFG": "6"}
	mockClient := &mockPowClient{}

	t.Run("test commit with valid UC ok", func(t *testing.T) {
		s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{PartitionParams: partitionParams}, mockClient, log)
		require.NoError(t, err)

		// create UC where IR.Hash = pendingStateHash
		blockHash := []byte("abcd")
		s.pendingStateHash = blockHash
		uc := &types.UnicityCertificate{
			InputRecord: &types.InputRecord{RoundNumber: 2, Hash: blockHash},
		}

		require.NoError(t, s.Commit(uc))
		require.Equal(t, blockHash, s.committedStateHash)
		require.Nil(t, s.pendingStateHash)
	})

	t.Run("test commit with invalid UC not ok", func(t *testing.T) {
		s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{PartitionParams: partitionParams}, mockClient, log)
		require.NoError(t, err)

		// create UC where IR.Hash = pendingStateHash
		s.pendingStateHash = []byte("dcba")
		uc := &types.UnicityCertificate{
			InputRecord: &types.InputRecord{RoundNumber: 2, Hash: []byte("abcd")},
		}

		err = s.Commit(uc)
		require.ErrorContains(t, err, "state mismatch")
	})

	t.Run("test commit initial UC", func(t *testing.T) {
		s, err := NewFGPTxSystem(types.PartitionDescriptionRecord{PartitionParams: partitionParams}, mockClient, log)
		require.NoError(t, err)

		s.pendingStateHash = nil
		initialUC := &types.UnicityCertificate{
			InputRecord: &types.InputRecord{},
		}
		err = s.Commit(initialUC)
		require.NoError(t, err)
		require.Nil(t, s.committedStateHash)
	})
}

type mockPowClient struct {
	tipHeight uint64
	tips      []powtypes.ChainTip
	blocks    map[string]*powtypes.BlockHeader
}

func (m *mockPowClient) GetTip(ctx context.Context) (*powtypes.BlockHeader, error) {
	return &powtypes.BlockHeader{Hash: "tiphash", Height: m.tipHeight}, nil
}

func (m *mockPowClient) GetBlockHeaderByHash(ctx context.Context, hash string) (*powtypes.BlockHeader, error) {
	if m.blocks != nil {
		if b, ok := m.blocks[hash]; ok {
			return b, nil
		}
	}
	return &powtypes.BlockHeader{Hash: hash, Height: 0}, nil
}

func (m *mockPowClient) GetBlockHeaderByHeight(ctx context.Context, height uint64) (*powtypes.BlockHeader, error) {
	return &powtypes.BlockHeader{Hash: hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), Height: height}, nil
}

func (m *mockPowClient) GetChainTips(ctx context.Context) ([]powtypes.ChainTip, error) {
	return m.tips, nil
}
