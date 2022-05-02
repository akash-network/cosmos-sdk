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
)

var (
	errCapacityInvalid = errors.New("capacity must be 1 or greater")
	errNoBlocks        = errors.New("rpc call for latest block returned nil")
)

func PollForBlocks(ctx context.Context, logger log.Logger, c client.Client, outCapacity ...int) (out <-chan abci.ResponseDeliverTx, err error) {
	logger = logger.With("cmp", "block-poller")

	// Create an outgoing channel for events
	outCap := 1
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

	if block == nil || block.Block == nil {
		return nil, errNoBlocks
	}

	height := block.Block.Height

	// Run until context dies
	go func() {
		err := pollForever(ctx, logger, c, height, outc)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		logger.Error("failed polling for events", "err", err)
	}()
	return outc, nil
}

type slidingAverage struct {
	data []float64
	sum  float64
	idx  int
}

func newSlidingAverage(initialValue float64, sampleCount int) *slidingAverage {
	result := &slidingAverage{
		data: make([]float64, sampleCount),
	}

	for i := range result.data {
		result.data[i] = initialValue
		result.sum += initialValue
	}

	return result
}

func (sa *slidingAverage) push(v float64) {
	// Deduct from the sum the value being evicted
	sa.sum -= sa.data[sa.idx]

	// Evict the value, replacing it with the new sample
	sa.data[sa.idx] = v
	// Add to the sum the new value
	sa.sum += v
	// Increment the destination for new samples
	sa.idx++
	// Loop around if past the end of the array
	if sa.idx == len(sa.data) {
		sa.idx = 0
	}
}

func (sa *slidingAverage) getAverage() float64 {
	return sa.sum / float64(len(sa.data))
}

func pollForever(ctx context.Context, logger log.Logger, c client.Client, startHeight int64, output chan<- abci.ResponseDeliverTx) error {
	const extraDelay = 100.0 // milliseconds
	const blockPeriod = time.Second * 5
	currentHeight := startHeight
	requiredDelay := blockPeriod

	// compute the sliding average of the time between blocks, starting at double the block period
	avg := newSlidingAverage(2*blockPeriod.Seconds(), 20)

	var lastBlock *coretypes.ResultBlock

	for {
		if requiredDelay > 0 {
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
		failureCount := 0
		for _, txn := range txs {
			gotTransaction := false
			for !gotTransaction {
				txResult, err := c.Tx(ctx, txn.Hash(), false)
				if err != nil {
					logger.Error("could not retrieve transaction from block", "height", block.Block.Height, "tx", txn.String())

					retryDelay := baseDelayBetweenTransactions
					if failureCount != 0 {
						retryDelay += 3 * time.Millisecond * time.Duration(math.Pow(1.5, float64(failureCount)))
					}
					if retryDelay > maxDelayBetweenTransactions {
						retryDelay = maxDelayBetweenTransactions
					}

					retryDelay += baseDelayBetweenTransactions * time.Duration(rand.Float64())

					if failureCount < math.MaxInt32 {
						failureCount += 1
					}

					select {
					case <-time.After(retryDelay):
					case <-ctx.Done():
						return ctx.Err()
					}
					continue
				}
				gotTransaction = true
				select {
				case output <- txResult.TxResult:
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
		nextBlockAt := block.Block.Time.Add(time.Millisecond * time.Duration(extraDelay+(1000.0*avg.getAverage())))
		requiredDelay = nextBlockAt.Sub(now) // may be negative
		lastBlock = block
	}
}
