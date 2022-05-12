package polling

import (
	"context"
	"errors"
	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/rpc/client"
	coretypes "github.com/tendermint/tendermint/rpc/core/types"
	"math"
	"math/rand"
	"strings"
	"time"
)

const (
	magicForBlockDoesNotExistErr = "must be less than or equal to the current blockchain height"
	baseDelayBetweenTransactions = 25 * time.Millisecond
	maxDelayBetweenTransactions  = 2500 * time.Millisecond
	maxDelayBetweenBlocks        = 10 * time.Second
)

var (
	errCapacityInvalid = errors.New("capacity must be 1 or greater")
	errNoBlocks        = errors.New("rpc call for latest block returned nil")
)

func PollForBlocks(ctx context.Context, logger log.Logger, c client.Client, outCapacity ...int) (out <-chan abci.ResponseDeliverTx, err error) {
	logger = logger.With("cmp", "block-poller")

	// Create an outgoing channel for events
	outCap := 0
	if len(outCapacity) > 0 {
		outCap = outCapacity[0]
		if outCap < 1 {
			return nil, errCapacityInvalid
		}
	}
	outc := make(chan abci.ResponseDeliverTx, outCap)

	// Get the current height
	block, err := c.Block(ctx, nil)
	if err != nil {
		return nil, err
	}

	// If a block isn't returned, this means the network was just started and hasn't produced a block. This is
	// an incredibly obtuse corner case, so just return an error saying this
	if block == nil || block.Block == nil {
		return nil, errNoBlocks
	}

	height := block.Block.Height

	// Run until context dies
	go func() {
		defer close(outc)
		err := pollForever(ctx, logger, c, height, outc)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		logger.Error("failed polling for events", "err", err)
	}()
	return outc, nil
}

func pollForever(ctx context.Context, logger log.Logger, c client.Client, startHeight int64, output chan<- abci.ResponseDeliverTx) error {
	const extraDelay = 100.0 * time.Millisecond
	const blockPeriod = time.Second * 5
	currentHeight := startHeight
	requiredDelay := blockPeriod

	// compute the sliding average of the time between blocks, starting at a value higher than block period
	avg := newSlidingAverage(1.5*blockPeriod.Seconds(), 20)

	var lastBlock *coretypes.ResultBlock

	for {
		if requiredDelay > 0 {
			// Cap maximum delay
			if requiredDelay > maxDelayBetweenBlocks {
				requiredDelay = maxDelayBetweenBlocks
			}
			delay := time.After(requiredDelay)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-delay:
			}
		}

		block, err := c.Block(ctx, &currentHeight)
		if err != nil {
			// Check to see if the block was requested too soon
			if strings.Contains(err.Error(), magicForBlockDoesNotExistErr) {
				// Wait a little bit longer, then ask for the block again
				requiredDelay = blockPeriod / 4
				requiredDelay += time.Duration(rand.Intn(250)) * time.Millisecond
				continue
			}
			logger.Error("could not retrieve block", "height", currentHeight, "err", err)

			requiredDelay = blockPeriod * 2
			requiredDelay += time.Duration(rand.Intn(250)) * time.Millisecond
			continue
		}
		currentHeight++

		txs := block.Block.Txs

		for _, txn := range txs {
			failureCount := uint32(0)
			for {
				txResult, err := c.Tx(ctx, txn.Hash(), false)
				if err == nil {
					select {
					case output <- txResult.TxResult:
					case <-ctx.Done():
						return ctx.Err()
					}
					break // transaction received and sent to output, terminate the inner loop
				}

				logger.Error("could not retrieve transaction from block", "height", block.Block.Height, "tx", txn.String())
				retryDelay := baseDelayBetweenTransactions
				if failureCount != 0 {
					retryDelay += 3 * time.Millisecond * time.Duration(math.Pow(1.5, float64(failureCount)))
				}
				retryDelay += baseDelayBetweenTransactions * (time.Millisecond * time.Duration(rand.Float64()*10))
				if retryDelay > maxDelayBetweenTransactions {
					retryDelay = maxDelayBetweenTransactions
				}
				if failureCount < math.MaxUint32 {
					failureCount += 1
				}

				select {
				case <-time.After(retryDelay):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}

		now := time.Now()
		// Update the sliding average
		if nil != lastBlock {
			blockTime := block.Block.Time.Sub(lastBlock.Block.Time)
			avg.push(blockTime.Seconds())
		}
		nextBlockAt := block.Block.Time.Add(time.Millisecond*time.Duration(1000.0*avg.getAverage()) + extraDelay)
		requiredDelay = nextBlockAt.Sub(now) // may be negative
		lastBlock = block
	}
}
