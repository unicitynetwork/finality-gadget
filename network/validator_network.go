package network

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/finality-gadget/network/protocol/blockproposal"
	"github.com/unicitynetwork/finality-gadget/network/protocol/certification"
	"github.com/unicitynetwork/finality-gadget/network/protocol/handshake"
	"github.com/unicitynetwork/finality-gadget/network/protocol/replication"
)

const (
	// Partition node protocols
	ProtocolBlockProposal         = "/ab/block-proposal/0.0.1"
	ProtocolLedgerReplicationReq  = "/ab/replication-req/0.0.1"
	ProtocolLedgerReplicationResp = "/ab/replication-resp/0.0.1"

	// BFT protocols
	ProtocolHandshake           = "/ab/handshake/0.0.1"
	ProtocolBlockCertification  = "/ab/block-certification/0.0.1"
	ProtocolUnicityCertificates = "/ab/certificates/0.0.1"
)

var DefaultValidatorNetworkOptions = ValidatorNetworkOptions{
	ReceivedChannelCapacity:          1000,
	BlockCertificationTimeout:        300 * time.Millisecond,
	BlockProposalTimeout:             300 * time.Millisecond,
	LedgerReplicationRequestTimeout:  300 * time.Millisecond,
	LedgerReplicationResponseTimeout: 300 * time.Millisecond,
	HandshakeTimeout:                 300 * time.Millisecond,
}

type (
	ValidatorNetworkOptions struct {
		// How many messages will be buffered (ReceivedChannel) in case of slow consumer.
		// Once buffer is full messages will be dropped (ie not processed)
		// until consumer catches up.
		ReceivedChannelCapacity uint

		// timeout configurations for Send operations.
		// timeout values are per receiver, ie when calling Send with multiple receivers
		// each receiver will have its own timeout. The context used with Send call can
		// be used to set timeout for whole Send call.

		BlockCertificationTimeout        time.Duration
		BlockProposalTimeout             time.Duration
		LedgerReplicationRequestTimeout  time.Duration
		LedgerReplicationResponseTimeout time.Duration
		HandshakeTimeout                 time.Duration
	}

	node interface {
		PartitionID() types.PartitionID
		ShardID() types.ShardID
		Peer() *Peer
	}

	ValidatorNetwork struct {
		*LibP2PNetwork
		node                 node
		gsSubscriptionBlock  *pubsub.Subscription
		gsCancelHandleBlocks context.CancelFunc
	}
)

/*
NewLibP2PValidatorNetwork creates a new LibP2PNetwork based validator network.
*/
func NewLibP2PValidatorNetwork(ctx context.Context, node node, opts ValidatorNetworkOptions, log *slog.Logger) (*ValidatorNetwork, error) {
	base, err := NewLibP2PNetwork(node.Peer(), opts.ReceivedChannelCapacity, log)
	if err != nil {
		return nil, err
	}

	n := &ValidatorNetwork{
		LibP2PNetwork: base,
		node:          node,
	}

	sendProtocolDescriptions := []SendProtocolDescription{
		{
			ProtocolID: ProtocolLedgerReplicationReq,
			Timeout:    opts.LedgerReplicationRequestTimeout,
			MsgType:    replication.LedgerReplicationRequest{}},
		{
			ProtocolID: ProtocolLedgerReplicationResp,
			Timeout:    opts.LedgerReplicationResponseTimeout,
			MsgType:    replication.LedgerReplicationResponse{},
		},
		{
			ProtocolID: ProtocolBlockProposal,
			Timeout:    opts.BlockProposalTimeout,
			MsgType:    blockproposal.BlockProposal{},
		},
		{
			ProtocolID: ProtocolBlockCertification,
			Timeout:    opts.BlockCertificationTimeout,
			MsgType:    certification.BlockCertificationRequest{},
		},
		{
			ProtocolID: ProtocolHandshake,
			Timeout:    opts.HandshakeTimeout,
			MsgType:    handshake.Handshake{},
		},
	}
	if err = n.RegisterSendProtocols(sendProtocolDescriptions); err != nil {
		return nil, fmt.Errorf("registering send protocols: %w", err)
	}

	receiveProtocolDescriptions := []ReceiveProtocolDescription{
		{
			ProtocolID: ProtocolLedgerReplicationReq,
			TypeFn:     func() any { return &replication.LedgerReplicationRequest{} },
		},
		{
			ProtocolID: ProtocolLedgerReplicationResp,
			TypeFn:     func() any { return &replication.LedgerReplicationResponse{} },
		},
	}
	if err = n.RegisterReceiveProtocols(receiveProtocolDescriptions); err != nil {
		return nil, fmt.Errorf("registering receive protocols: %w", err)
	}
	return n, nil
}

func (n *ValidatorNetwork) RegisterValidatorProtocols() error {
	receiveProtocols := []ReceiveProtocolDescription{
		{
			ProtocolID: ProtocolBlockProposal,
			TypeFn:     func() any { return &blockproposal.BlockProposal{} },
		},
		{
			ProtocolID: ProtocolUnicityCertificates,
			TypeFn:     func() any { return &certification.CertificationResponse{} },
		},
	}
	return n.RegisterReceiveProtocols(receiveProtocols)
}
