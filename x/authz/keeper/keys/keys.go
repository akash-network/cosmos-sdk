package keys

import (
	"bytes"
	"encoding/hex"
	"fmt"
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
	GrantKey             = []byte{0x01} // prefix for each key
	GrantQueuePrefix     = []byte{0x02}
	GranteeGranterKey    = []byte{0x03} // reverse prefix to get grants by grantee
	GranteeMsgTypeUrlKey = []byte{0x04} // reverse prefix to get grantee's grants by msgTypeUrl
)

var lenTime = len(sdk.FormatTimeBytes(time.Now()))

// GrantStoreKey - return authorization store key
// Items are stored with the following key: values
//
// - 0x01<granterAddressLen (1 Byte)><granterAddress_Bytes><granteeAddressLen (1 Byte)><granteeAddress_Bytes><msgType_Bytes>: Grant
func GrantStoreKey(grantee, granter sdk.AccAddress, msgType string) []byte {
	buf := &bytes.Buffer{}

	buf.Write(GrantKey)
	if !granter.Empty() {
		data := address.MustLengthPrefix(granter)
		buf.Write(data)

		if !grantee.Empty() {
			data = address.MustLengthPrefix(grantee)
			buf.Write(data)

			if msgType != "" {
				data = conv.UnsafeStrToBytes(msgType)

				buf.WriteByte(byte(len(data)))
				buf.Write(data)
			}
		}
	}

	return buf.Bytes()
}

// GranteeGranterStoreKey - return authorization store key
// Items are stored with the following key: values
//
// - 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes><msgTypeAddressLen (1 Byte)><msgType_Bytes>
func GranteeGranterStoreKey(grantee sdk.AccAddress, granter sdk.AccAddress, msgType string) []byte {
	buf := &bytes.Buffer{}

	buf.Write(GranteeGranterKey)
	if !grantee.Empty() {
		data := address.MustLengthPrefix(grantee)
		buf.Write(data)

		if !granter.Empty() {
			data = address.MustLengthPrefix(granter)
			buf.Write(data)

			if msgType != "" {
				data = conv.UnsafeStrToBytes(msgType)

				buf.WriteByte(byte(len(data)))
				buf.Write(data)
			}
		}
	}

	return buf.Bytes()
}

// GranteeMsgTypeUrlStoreKey - return authorization store key
// Items are stored with the following key: values
//
// - 0x04<granteeAddressLen (1 Byte)><granteeAddress_Bytes><msgTypeAddressLen (1 Byte)><msgType_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
func GranteeMsgTypeUrlStoreKey(grantee sdk.AccAddress, msgType string, granter sdk.AccAddress) []byte {
	buf := &bytes.Buffer{}

	buf.Write(GranteeMsgTypeUrlKey)

	if !grantee.Empty() {
		data := address.MustLengthPrefix(grantee)
		buf.Write(data)

		if msgType != "" {
			data = conv.UnsafeStrToBytes(msgType)

			buf.WriteByte(byte(len(data)))
			buf.Write(data)

			if !granter.Empty() {
				data = address.MustLengthPrefix(granter)
				buf.Write(data)
			}
		}
	}

	return buf.Bytes()
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

// ParseGranteeGranterStoreKey key is of format:
// 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes><msgTypeAddressLen (1 Byte)><msgType_Bytes>
func ParseGranteeGranterStoreKey(key []byte) (sdk.AccAddress, sdk.AccAddress, string) {
	// key is of format:
	// 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
	kv.AssertKeyAtLeastLength(key, len(GranteeGranterKey)+1)
	if !bytes.HasPrefix(key, GranteeGranterKey) {
		panic(fmt.Sprintf("invalid key prefix. expected 0x%s, actual 0x%s", hex.EncodeToString(key[:1]), GranteeGranterKey))
	}

	// remove a prefix key
	key = key[len(GranteeGranterKey):]

	// decode grantee address
	kv.AssertKeyAtLeastLength(key, 1)
	dataLen := int(key[0])
	key = key[1:]
	kv.AssertKeyAtLeastLength(key, dataLen)
	granteeAddr := key[:dataLen]
	key = key[dataLen:]

	// decode granter address
	kv.AssertKeyAtLeastLength(key, 1)
	dataLen = int(key[0])
	key = key[1:]
	kv.AssertKeyAtLeastLength(key, dataLen)
	granterAddr := key[:dataLen]
	key = key[dataLen:]

	// decode msgTypeUrl
	kv.AssertKeyAtLeastLength(key, 1)
	dataLen = int(key[0])
	key = key[1:]
	kv.AssertKeyLength(key, dataLen)
	msgType := conv.UnsafeBytesToStr(key[:dataLen])

	return granteeAddr, granterAddr, msgType
}

// ParseGranteeMsgTypeStoreKey key is of format:
// 0x04<granteeAddressLen (1 Byte)><granteeAddress_Bytes><msgTypeAddressLen (1 Byte)><msgType_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
func ParseGranteeMsgTypeStoreKey(key []byte) (sdk.AccAddress, string, sdk.AccAddress) {
	// key is of format:
	// 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
	kv.AssertKeyAtLeastLength(key, len(GranteeMsgTypeUrlKey)+1)
	if !bytes.HasPrefix(key, GranteeMsgTypeUrlKey) {
		panic(fmt.Sprintf("invalid key prefix. expected 0x%s, actual 0x%s", hex.EncodeToString(key[:1]), GranteeMsgTypeUrlKey))
	}

	// remove a prefix key
	key = key[len(GranteeMsgTypeUrlKey):]

	// decode grantee address
	dataLen := int(key[0])
	key = key[1:]
	kv.AssertKeyAtLeastLength(key, dataLen)
	granteeAddr := key[:dataLen]
	key = key[dataLen:]

	// decode msgTypeUrl
	kv.AssertKeyAtLeastLength(key, 1)
	dataLen = int(key[0])
	key = key[1:]
	kv.AssertKeyAtLeastLength(key, dataLen)
	msgType := conv.UnsafeBytesToStr(key[:dataLen])
	key = key[dataLen:]

	// decode granter address
	kv.AssertKeyAtLeastLength(key, 1)
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
	skey := GranteeGranterStoreKey(grantee, granter, msgType)
	mkey := GranteeMsgTypeUrlStoreKey(grantee, msgType, granter)

	scount := sdkmath.NewInt(1)
	mcount := sdkmath.NewInt(1)

	if exists, _ := store.Has(skey); !exists {
		err := store.Set(skey, scount.BigInt().Bytes())
		if err != nil {
			return err
		}
		//val, err := store.Get(skey)
		//if err != nil {
		//	return err
		//}
		//
		//bi := new(big.Int).SetBytes(val).Int64()
		//
		//scount = scount.AddRaw(bi + 1)
	}

	if exists, _ := store.Has(mkey); !exists {
		err := store.Set(mkey, mcount.BigInt().Bytes())
		if err != nil {
			return err
		}

		//val, err := store.Get(mkey)
		//if err != nil {
		//	return err
		//}
		//
		//bi := new(big.Int).SetBytes(val).Int64()
		//
		//mcount = mcount.AddRaw(bi + 1)
	}

	return nil
}
