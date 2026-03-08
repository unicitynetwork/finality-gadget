package logger

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/finality-gadget/logger"
)

func Test_loggers_json_output(t *testing.T) {
	log, err := logger.New(&logger.LogConfiguration{OutputPath: "stdout", Level: "debug", Format: "ecs"})
	if err != nil {
		for ; err != nil; err = errors.Unwrap(err) {
			t.Logf("%T : %v", err, err)
		}
		t.Fatalf("initializing logger: %v", err)
	}

	nodeID, err := peer.Decode("16Uiu2HAm7xi5YRtfsXd4w7UXomcd5T75o44JmrYrAedS7NGszzek")
	if err != nil {
		t.Errorf("failed to decode peer id: %v", err)
	}

	type foo struct {
		V string
	}

	log.LogAttrs(context.Background(),
		slog.LevelInfo,
		"some information",
		logger.Error(fmt.Errorf("additional error message")),
		logger.NodeID(nodeID),
		logger.Data(&foo{"bar"}),
	)
}
