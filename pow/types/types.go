package types

import "context"

type (
	Client interface {
		// GetTip returns the current tip of the active PoW chain.
		GetTip(ctx context.Context) (*BlockHeader, error)

		// GetBlockHeaderByHash returns a block by its hash.
		GetBlockHeaderByHash(ctx context.Context, hash string) (*BlockHeader, error)

		// GetBlockHeaderByHeight returns the block at a specific height.
		GetBlockHeaderByHeight(ctx context.Context, height uint64) (*BlockHeader, error)

		// GetChainTips returns information about all known branch tips in the block tree.
		GetChainTips(ctx context.Context) ([]ChainTip, error)
	}

	BlockHeader struct {
		Hash              string  `json:"hash"`
		Confirmations     int     `json:"confirmations"`
		Height            uint64  `json:"height"`
		Version           int     `json:"version"`
		VersionHex        string  `json:"versionHex"`
		Time              int64   `json:"time"`
		Mediantime        int64   `json:"mediantime"`
		Nonce             uint64  `json:"nonce"`
		Bits              string  `json:"bits"`
		Difficulty        float64 `json:"difficulty"`
		Chainwork         string  `json:"chainwork"`
		PreviousBlockHash string  `json:"previousblockhash"`
		RxHash            string  `json:"rx_hash"`
	}

	ChainTip struct {
		Height    uint64 `json:"height"`
		Hash      string `json:"hash"`
		BranchLen uint64 `json:"branchlen"`
		Status    string `json:"status"`
	}
)

// IsActive returns true if the block is part of the active chain.
// In PoW RPCs, only blocks in the active chain have Confirmations > 0.
// Orphaned or inactive blocks return Confirmations <= 0 (typically -1).
func (b *BlockHeader) IsActive() bool {
	return b.Confirmations > 0
}
