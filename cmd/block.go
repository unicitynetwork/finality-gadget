package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
)

func newBlockCmd(flags *cliFlags) *cobra.Command {
	blockCmd := &cobra.Command{
		Use:   "block <round>",
		Args:  cobra.ExactArgs(1),
		Short: "Load and print a block by round number (the blocks.db must not be locked by any process)",
		RunE: func(cmd *cobra.Command, args []string) error {
			round, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid round number: %w", err)
			}

			// TODO should create read only constructor
			dbPath := flags.pathWithDefault(flags.BlockDBFile, blockDBFileName)
			blockDB, err := boltdb.New(dbPath)
			if err != nil {
				return fmt.Errorf("error opening block database (db in use my another process?): %w", err)
			}
			defer blockDB.Close()

			var b types.Block
			found, err := blockDB.Read(util.Uint64ToBytes(round), &b)
			if err != nil {
				return fmt.Errorf("failed to read block %v from db: %w", round, err)
			}
			if !found {
				return fmt.Errorf("block %v not found", round)
			}

			// Format for JSON output
			type BlockForJSON struct {
				Header             *types.Header              `json:"header"`
				Transactions       []*types.TransactionRecord `json:"transactions"`
				UnicityCertificate *types.UnicityCertificate  `json:"unicity_certificate"`
			}

			blockJSON := BlockForJSON{
				Header:       b.Header,
				Transactions: b.Transactions,
			}

			// unicity certificate is stored as raw cbor bytes which we need to convert actual object
			uc := &types.UnicityCertificate{Version: 1}
			if err := types.Cbor.Unmarshal(b.UnicityCertificate, uc); err == nil {
				blockJSON.UnicityCertificate = uc
			}

			output, err := json.MarshalIndent(blockJSON, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal block to JSON: %w", err)
			}

			fmt.Println(string(output))
			return nil
		},
	}
	blockCmd.Flags().StringVar(&flags.BlockDBFile, "block-db", "", "path to the block database (default: $FGP_HOME/blocks.db)")
	return blockCmd
}
