package keys

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	corestoretypes "cosmossdk.io/core/store"
	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/internal/conv"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
	"github.com/cosmos/cosmos-sdk/types/kv"
)

// Keys for store prefixes
// Items are stored with the following key: values
//
// - 0x01<grant_Bytes>: Grant
// - 0x02<grant_expiration_Bytes>: GrantQueueItem
// - 0x03<grantee_Bytes>: Grant by grantee
// - 0x04<grantee msg type>: grant by grantee and msgTypeUrl
var (
	GrantKey         = []byte{0x01} // prefix for each key
	GrantQueuePrefix = []byte{0x02}
	GranteeKey       = []byte{0x03} // reverse prefix to get grants by grantee
	GranteeMsgKey    = []byte{0x04} // reverse prefix to get grantee's grants by msgTypeUrl
)

var lenTime = len(sdk.FormatTimeBytes(time.Now()))

// GrantStoreKey - return authorization store key
// Items are stored with the following key: values
//
// - 0x01<granterAddressLen (1 Byte)><granterAddress_Bytes><granteeAddressLen (1 Byte)><granteeAddress_Bytes><msgType_Bytes>: Grant
func GrantStoreKey(grantee, granter sdk.AccAddress, msgType string) []byte {
	m := conv.UnsafeStrToBytes(msgType)
	granter = address.MustLengthPrefix(granter)
	grantee = address.MustLengthPrefix(grantee)
	key := sdk.AppendLengthPrefixedBytes(GrantKey, granter, grantee, m)

	return key
}

// GranteeStoreKey - return authorization store key
// Items are stored with the following key: values
//
// - 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
func GranteeStoreKey(grantee sdk.AccAddress, granter sdk.AccAddress) []byte {
	grantee = address.MustLengthPrefix(grantee)
	granter = address.MustLengthPrefix(granter)

	key := sdk.AppendLengthPrefixedBytes(GranteeKey, grantee, granter)

	return key
}

// GranteeMsgStoreKey - return authorization store key
// Items are stored with the following key: values
//
// - 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><msgTypeAddressLen (1 Byte)><msgType_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
func GranteeMsgStoreKey(grantee sdk.AccAddress, msgType string, granter sdk.AccAddress) []byte {
	args := make([][]byte, 0, 4)

	args = append(args, GranteeMsgKey)
	args = append(args, address.MustLengthPrefix(grantee))

	if msgType != "" {
		args = append(args, conv.UnsafeStrToBytes(msgType))

		if granter != nil {
			args = append(args, address.MustLengthPrefix(granter))
		}
	}

	key := sdk.AppendLengthPrefixedBytes(args...)

	return key
}

// ParseGrantStoreKey - split granter, grantee address and msg type from the authorization key
func ParseGrantStoreKey(key []byte) (granterAddr, granteeAddr sdk.AccAddress, msgType string) {
	// key is of format:
	// 0x01<granterAddressLen (1 Byte)><granterAddress_Bytes><granteeAddressLen (1 Byte)><granteeAddress_Bytes><msgType_Bytes>

	granterAddrLen, granterAddrLenEndIndex := sdk.ParseLengthPrefixedBytes(key, 1, 1) // ignore key[0] since it is a prefix key
	granterAddr, granterAddrEndIndex := sdk.ParseLengthPrefixedBytes(key, granterAddrLenEndIndex+1, int(granterAddrLen[0]))

	granteeAddrLen, granteeAddrLenEndIndex := sdk.ParseLengthPrefixedBytes(key, granterAddrEndIndex+1, 1)
	granteeAddr, granteeAddrEndIndex := sdk.ParseLengthPrefixedBytes(key, granteeAddrLenEndIndex+1, int(granteeAddrLen[0]))

	kv.AssertKeyAtLeastLength(key, granteeAddrEndIndex+1)
	return granterAddr, granteeAddr, conv.UnsafeBytesToStr(key[(granteeAddrEndIndex + 1):])
}

// ParseGrantQueueKey split expiration time, granter and grantee from the grant queue key
func ParseGrantQueueKey(key []byte) (time.Time, sdk.AccAddress, sdk.AccAddress, error) {
	// key is of format:
	// 0x02<grant_expiration_Bytes><granterAddress_Bytes><granteeAddressLen (1 Byte)><granteeAddress_Bytes>

	expBytes, expEndIndex := sdk.ParseLengthPrefixedBytes(key, 1, lenTime)

	exp, err := sdk.ParseTimeBytes(expBytes)
	if err != nil {
		return exp, nil, nil, err
	}

	granterAddrLen, granterAddrLenEndIndex := sdk.ParseLengthPrefixedBytes(key, expEndIndex+1, 1)
	granter, granterEndIndex := sdk.ParseLengthPrefixedBytes(key, granterAddrLenEndIndex+1, int(granterAddrLen[0]))

	granteeAddrLen, granteeAddrLenEndIndex := sdk.ParseLengthPrefixedBytes(key, granterEndIndex+1, 1)
	grantee, _ := sdk.ParseLengthPrefixedBytes(key, granteeAddrLenEndIndex+1, int(granteeAddrLen[0]))

	return exp, granter, grantee, nil
}

// ParseGranteeStoreKey key is of format:
// 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
func ParseGranteeStoreKey(key []byte) (sdk.AccAddress, sdk.AccAddress) {
	// key is of format:
	// 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
	kv.AssertKeyAtLeastLength(key, 2)
	if !bytes.Equal(key[:1], GranteeKey) {
		panic(fmt.Sprintf("invalid key prefix. expected 0x%s, actual 0x%s", hex.EncodeToString(key[:1]), GranteeKey))
	}

	key = key[1:] // remove a prefix key

	// decode grantee address
	dataLen := int(key[0])
	kv.AssertKeyAtLeastLength(key, dataLen)
	key = key[1:]
	granteeAddr := key[:dataLen]

	// decode granter address
	kv.AssertKeyAtLeastLength(key, 1)
	key = key[dataLen:]
	dataLen = int(key[0])
	key = key[1:]
	kv.AssertKeyLength(key, dataLen)
	granterAddr := key

	return granteeAddr, granterAddr
}

// ParseGranteeMsgStoreKey key is of format:
// 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
func ParseGranteeMsgStoreKey(key []byte) (sdk.AccAddress, string, sdk.AccAddress) {
	// key is of format:
	// 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
	kv.AssertKeyAtLeastLength(key, 2)
	if !bytes.Equal(key[:1], GranteeMsgKey) {
		panic(fmt.Sprintf("invalid key prefix. expected 0x%s, actual 0x%s", hex.EncodeToString(key[:1]), GranteeMsgKey))
	}

	// decode grantee address
	key = key[1:] // remove a prefix key
	dataLen := int(key[0])
	kv.AssertKeyAtLeastLength(key, dataLen)
	key = key[1:]
	granteeAddr := key[:dataLen]

	// decode msgTypeUrl
	kv.AssertKeyAtLeastLength(key, 1)
	key = key[dataLen:]
	dataLen = int(key[0])
	kv.AssertKeyAtLeastLength(key, dataLen)
	key = key[1:]
	msgType := conv.UnsafeBytesToStr(key[:dataLen])
	key = key[dataLen:]

	// decode granter address
	dataLen = int(key[0])
	key = key[1:]
	kv.AssertKeyLength(key, dataLen)
	granterAddr := key

	return granteeAddr, msgType, granterAddr
}

// GrantQueueKey - return grant queue store key. If a given grant doesn't have a defined
// expiration, then it should not be used in the pruning queue.
// Key format is:
//
//	0x02<expiration><granterAddressLen (1 Byte)><granterAddressBytes><granteeAddressLen (1 Byte)><granteeAddressBytes>: GrantQueueItem
func GrantQueueKey(expiration time.Time, granter, grantee sdk.AccAddress) []byte {
	exp := sdk.FormatTimeBytes(expiration)
	granter = address.MustLengthPrefix(granter)
	grantee = address.MustLengthPrefix(grantee)

	return sdk.AppendLengthPrefixedBytes(GrantQueuePrefix, exp, granter, grantee)
}

// GrantQueueTimePrefix - return grant queue time prefix
func GrantQueueTimePrefix(expiration time.Time) []byte {
	return append(GrantQueuePrefix, sdk.FormatTimeBytes(expiration)...)
}

// FirstAddressFromGrantStoreKey parses the first address only
func FirstAddressFromGrantStoreKey(key []byte) sdk.AccAddress {
	addrLen := key[0]
	return key[1 : 1+addrLen]
}

func IncGranteeGrants(store corestoretypes.KVStore, grantee, granter sdk.AccAddress, msgType string) error {
	skey := GranteeStoreKey(grantee, granter)
	mkey := GranteeMsgStoreKey(grantee, msgType, granter)

	scount := sdkmath.NewInt(1)
	mcount := sdkmath.NewInt(1)

	if exists, _ := store.Has(skey); exists {
		val, err := store.Get(skey)
		if err != nil {
			return err
		}

		bi := new(big.Int).SetBytes(val).Int64()

		scount = scount.AddRaw(bi + 1)
	}

	if exists, _ := store.Has(mkey); exists {
		val, err := store.Get(mkey)
		if err != nil {
			return err
		}

		bi := new(big.Int).SetBytes(val).Int64()

		mcount = mcount.AddRaw(bi + 1)
	}

	err := store.Set(skey, scount.BigInt().Bytes())
	if err != nil {
		return err
	}

	err = store.Set(mkey, mcount.BigInt().Bytes())
	if err != nil {
		return err
	}

	return nil
}
