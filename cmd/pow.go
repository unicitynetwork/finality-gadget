package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/unicitynetwork/finality-gadget/pow"
)

func newPowCmd(flags *cliFlags) *cobra.Command {
	powCmd := &cobra.Command{
		Use:   "pow",
		Short: "Wrapper commands for the internal PoW RPC client for testing",
	}

	powCmd.AddCommand(newPowGetTipCmd(flags))
	powCmd.AddCommand(newPowGetBlockHeaderByHashCmd(flags))
	powCmd.AddCommand(newPowGetBlockHeaderByHeightCmd(flags))

	return powCmd
}

func newPowGetTipCmd(flags *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get-tip",
		Short: "Get the current tip of the PoW chain",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := pow.NewIPCClient(flags.PowSocketPath)
			tip, err := client.GetTip(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to get PoW chain tip: %w", err)
			}

			output, err := json.MarshalIndent(tip, "", "  ")
			if err != nil {
				return err
			}

			fmt.Println(string(output))
			return nil
		},
	}
}

func newPowGetBlockHeaderByHashCmd(flags *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get-block-header-by-hash <hash>",
		Short: "Get a PoW block header by its hash",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hash := args[0]
			client := pow.NewIPCClient(flags.PowSocketPath)
			block, err := client.GetBlockHeaderByHash(cmd.Context(), hash)
			if err != nil {
				return fmt.Errorf("failed to get PoW block: %w", err)
			}

			output, err := json.MarshalIndent(block, "", "  ")
			if err != nil {
				return err
			}

			fmt.Println(string(output))
			return nil
		},
	}
}

func newPowGetBlockHeaderByHeightCmd(flags *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get-block-header-by-height <height>",
		Short: "Get a PoW block header by its height in the active chain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			heightStr := args[0]
			height, err := strconv.ParseUint(heightStr, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid height: %w", err)
			}

			client := pow.NewIPCClient(flags.PowSocketPath)
			block, err := client.GetBlockHeaderByHeight(cmd.Context(), height)
			if err != nil {
				return fmt.Errorf("failed to get PoW block: %w", err)
			}

			output, err := json.MarshalIndent(block, "", "  ")
			if err != nil {
				return err
			}

			fmt.Println(string(output))
			return nil
		},
	}
}
