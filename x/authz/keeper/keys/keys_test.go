package keys

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
	bank "github.com/cosmos/cosmos-sdk/x/bank/types"
)

var (
	granter = sdk.AccAddress(ed25519.GenPrivKey().PubKey().Address())
	grantee = sdk.AccAddress(ed25519.GenPrivKey().PubKey().Address())
	msgType = bank.SendAuthorization{}.MsgTypeURL()
)

func TestGrantKey(t *testing.T) {
	require := require.New(t)
	key := GrantStoreKey(grantee, granter, msgType)
	require.Len(key, len(GrantKey)+len(address.MustLengthPrefix(grantee))+len(address.MustLengthPrefix(granter))+len([]byte(msgType)))

	granter1, grantee1, msgType1 := ParseGrantStoreKey(GrantStoreKey(grantee, granter, msgType))
	require.Equal(granter, granter1)
	require.Equal(grantee, grantee1)
	require.Equal(msgType1, msgType)
}

func TestGrantQueueKey(t *testing.T) {
	blockTime := time.Now().UTC()
	queueKey := GrantQueueKey(blockTime, granter, grantee)

	expiration, granter1, grantee1, err := ParseGrantQueueKey(queueKey)
	require.NoError(t, err)
	require.Equal(t, blockTime, expiration)
	require.Equal(t, granter, granter1)
	require.Equal(t, grantee, grantee1)
}

func TestGranteeKey(t *testing.T) {
	key := GranteeStoreKey(grantee, granter)

	require.Len(t, key, len(GranteeKey)+len(address.MustLengthPrefix(grantee))+len(address.MustLengthPrefix(granter)))

	grantee1, granter1 := ParseGranteeStoreKey(key)
	require.Equal(t, granter, granter1)
	require.Equal(t, grantee, grantee1)
}
