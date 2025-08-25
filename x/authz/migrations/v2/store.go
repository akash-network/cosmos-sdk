package v2

import (
	"context"

	corestoretypes "cosmossdk.io/core/store"
	"cosmossdk.io/store/prefix"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/internal/conv"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/cosmos/cosmos-sdk/x/authz/keeper/keys"
)

// MigrateStore performs in-place store migrations from v0.45 to v0.46. The
// migration includes:
//
// - pruning expired authorizations
// - create secondary index for pruning expired authorizations
func MigrateStore(ctx context.Context, storeService corestoretypes.KVStoreService, cdc codec.BinaryCodec) error {
	store := storeService.OpenKVStore(ctx)
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	err := store.Delete(keys.GranteeKey)
	if err != nil {
		return err
	}

	err = store.Delete(keys.GranteeMsgKey)
	if err != nil {
		return err
	}

	grantsStore := prefix.NewStore(runtime.KVStoreAdapter(store), keys.GrantKey)
	grantsIter := grantsStore.Iterator(nil, nil)
	defer func() {
		_ = grantsIter.Close()
	}()

	queueItems := make(map[string][]string)
	now := sdkCtx.BlockTime()
	for ; grantsIter.Valid(); grantsIter.Next() {
		var grant authz.Grant
		bz := grantsIter.Value()
		if err := cdc.Unmarshal(bz, &grant); err != nil {
			return err
		}

		// delete expired authorization
		// before 0.46 Expiration was required so it's safe to dereference
		if grant.Expiration.Before(now) {
			grantsStore.Delete(grantsIter.Key())
		} else {
			granter, grantee, msgType := ParseGrantKey(grantsIter.Key())
			// before 0.46 expiration was not a pointer, so now it's safe to dereference
			key := keys.GrantQueueKey(*grant.Expiration, granter, grantee)

			queueItem, ok := queueItems[conv.UnsafeBytesToStr(key)]
			if !ok {
				queueItems[string(key)] = []string{msgType}
			} else {
				queueItem = append(queueItem, msgType)
				queueItems[string(key)] = queueItem
			}

			err := keys.IncGranteeGrants(store, grantee, granter, msgType)
			if err != nil {
				return err
			}
		}
	}

	for key, v := range queueItems {
		bz, err := cdc.Marshal(&authz.GrantQueueItem{
			MsgTypeUrls: v,
		})
		if err != nil {
			return err
		}
		err = store.Set(conv.UnsafeStrToBytes(key), bz)
		if err != nil {
			return err
		}
	}

	return nil
}
