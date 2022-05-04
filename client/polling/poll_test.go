package polling

import (
	"context"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/abci/example/kvstore"
	"github.com/tendermint/tendermint/libs/log"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	"github.com/tendermint/tendermint/rpc/client"
	rpclocal "github.com/tendermint/tendermint/rpc/client/local"
	rpctest "github.com/tendermint/tendermint/rpc/test"
	"io/ioutil"
	"os"
	"testing"
	"time"
)



func TestPollForBlocksError(t *testing.T) {
	ch, err := PollForBlocks(context.Background(), log.TestingLogger(), nil, 0)
	require.Error(t, err)
	require.Nil(t, ch)
	require.ErrorIs(t, err, errCapacityInvalid)

	ch, err = PollForBlocks(context.Background(), log.TestingLogger(), nil, -1)
	require.Error(t, err)
	require.Nil(t, ch)
	require.ErrorIs(t, err, errCapacityInvalid)
}

func MakeTxKV() ([]byte, []byte, []byte) {
	k := []byte(tmrand.Str(8))
	v := []byte(tmrand.Str(8))
	return k, v, append(k, append([]byte("="), v...)...)
}

func TestPollForBlocks(t *testing.T) {
	// start a tendermint node (and kvstore) in the background to test against
	dir, err := ioutil.TempDir("/tmp", "polling-test")
	if err != nil {
		panic(err)
	}

	app := kvstore.NewPersistentKVStoreApplication(dir)
	node := rpctest.StartTendermint(app)
	defer func() {
		// and shut down proper at the end
		rpctest.StopTendermint(node)
		_ = os.RemoveAll(dir)
	}()

	c := rpclocal.New(node)
	err = client.WaitForHeight(c, 1, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	ch, err := PollForBlocks(ctx, log.TestingLogger(), c)
	require.NoError(t, err)
	require.NotNil(t, ch)

	select {
	case <-ch:
		t.Fatal("should not have received a transaction yet")
	default:
	}

	_, _, tx := MakeTxKV()
	broadcastResult, err := c.BroadcastTxCommit(ctx, tx)
	require.NoError(t, err)
	require.NotNil(t, broadcastResult)
	require.Equal(t, broadcastResult.DeliverTx.Code, uint32(0))

	select {
	case txn := <-ch:
		require.NotNil(t, txn)
		require.NotEmpty(t, txn.GetEvents())
		require.Equal(t, txn.GetEvents(), broadcastResult.DeliverTx.GetEvents())
	case <-ctx.Done():
		t.Fatal("timed out waiting on transaction event")
	}

	txnCount := 1 + tmrand.Intn(100)

	for i := 0; i != txnCount; i++ {
		_, _, tx := MakeTxKV()
		broadcastResult, err := c.BroadcastTxCommit(ctx, tx)
		require.NoError(t, err)
		require.NotNil(t, broadcastResult)
		require.Equal(t, broadcastResult.DeliverTx.Code, uint32(0))
	}

	rxCnt := 0
	for rxCnt != txnCount {
		select {
		case txn := <-ch:
			require.NotNil(t, txn)
			require.NotEmpty(t, txn.GetEvents())
			rxCnt++
		case <-ctx.Done():
			t.Fatal("timed out waiting on transaction event")
		}
	}
	require.Equal(t, rxCnt, txnCount)
}
