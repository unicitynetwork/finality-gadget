package trustbase

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func NewTrustBase(t *testing.T, signers ...abcrypto.Signer) types.RootTrustBase {
	var nodes []*types.NodeInfo
	signerMap := make(map[string]abcrypto.Signer)
	for _, s := range signers {
		v, err := s.Verifier()
		require.NoError(t, err)
		pubKeyBytes, err := v.MarshalPublicKey()
		require.NoError(t, err)
		pubKey, err := crypto.UnmarshalSecp256k1PublicKey(pubKeyBytes)
		require.NoError(t, err)
		peerID, err := peer.IDFromPublicKey(pubKey)
		require.NoError(t, err)

		nodes = append(nodes, &types.NodeInfo{
			NodeID: peerID.String(),
			SigKey: pubKeyBytes,
			Stake:  1,
		})
		signerMap[peerID.String()] = s
	}
	tb, err := types.NewTrustBase(5, nodes)
	require.NoError(t, err)

	for nodeID, signer := range signerMap {
		require.NoError(t, tb.Sign(nodeID, signer))
	}
	return tb
}

func NewTrustBaseFromSigners(t *testing.T, signers map[string]abcrypto.Signer) types.RootTrustBase {
	var nodes []*types.NodeInfo
	for nodeID, v := range signers {
		verifier, err := v.Verifier()
		require.NoError(t, err)
		nodes = append(nodes, NewNodeInfoFromVerifier(t, nodeID, verifier))
	}
	tb, err := types.NewTrustBase(5, nodes)
	require.NoError(t, err)
	for nodeID, signer := range signers {
		require.NoError(t, tb.Sign(nodeID, signer))
	}
	return tb
}

func NewNodeInfoFromVerifier(t *testing.T, nodeID string, sigVerifier abcrypto.Verifier) *types.NodeInfo {
	sigKey, err := sigVerifier.MarshalPublicKey()
	require.NoError(t, err)
	return &types.NodeInfo{
		NodeID: nodeID,
		SigKey: sigKey,
		Stake:  1,
	}
}
