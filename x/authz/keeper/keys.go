package keeper

import (
	"github.com/cosmos/cosmos-sdk/internal/conv"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/address"
	"github.com/cosmos/cosmos-sdk/types/kv"
	"github.com/cosmos/cosmos-sdk/x/authz"
)

// - 0x01<grant_Bytes>: Grant
// - 0x03<grant_Bytes>: Grant
var (
	GrantKey   = []byte{0x01} // prefix for each key
	GranteeKey = []byte{0x03} // prefix for each key
)

// StoreKey is the store key string for authz
const StoreKey = authz.ModuleName

// grantStoreKey - return authorization store key
// Items are stored with the following key: values
//
// - 0x01<granterAddressLen (1 Byte)><granterAddress_Bytes><granteeAddressLen (1 Byte)><granteeAddress_Bytes><msgType_Bytes>: Grant
func grantStoreKey(grantee sdk.AccAddress, granter sdk.AccAddress, msgType string) []byte {
	m := conv.UnsafeStrToBytes(msgType)
	granter = address.MustLengthPrefix(granter)
	grantee = address.MustLengthPrefix(grantee)

	l := 1 + len(grantee) + len(granter) + len(m)
	key := make([]byte, l)
	copy(key, GrantKey)
	copy(key[1:], granter)
	copy(key[1+len(granter):], grantee)
	copy(key[l-len(m):], m)

	return key
}

// granteeStoreKey - return authorization store key
// Items are stored with the following key: values
//
// - 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
func granteeStoreKey(grantee sdk.AccAddress, granter sdk.AccAddress) []byte {
	grantee = address.MustLengthPrefix(grantee)
	granter = address.MustLengthPrefix(granter)

	l := len(GranteeKey) + len(grantee) + len(granter)
	key := make([]byte, l)

	copy(key, GranteeKey)
	copy(key[1:], grantee)
	copy(key[1+len(grantee):], granter)

	return key
}

// AddressesFromGrantStoreKey - split granter & grantee address from the authorization key
func AddressesFromGrantStoreKey(key []byte) (sdk.AccAddress, sdk.AccAddress) {
	// key is of format:
	// 0x01<granterAddressLen (1 Byte)><granterAddress_Bytes><granteeAddressLen (1 Byte)><granteeAddress_Bytes><msgType_Bytes>
	kv.AssertKeyAtLeastLength(key, 2)
	granterAddrLen := key[1] // remove prefix key
	kv.AssertKeyAtLeastLength(key, int(3+granterAddrLen))
	granterAddr := key[2 : 2+granterAddrLen]
	granteeAddrLen := int(key[2+granterAddrLen])
	kv.AssertKeyAtLeastLength(key, 4+int(granterAddrLen+byte(granteeAddrLen)))
	granteeAddr := key[3+granterAddrLen : 3+granterAddrLen+byte(granteeAddrLen)]

	return granterAddr, granteeAddr
}

func AddressesFromGranteeStoreKey(key []byte) (sdk.AccAddress, sdk.AccAddress) {
	// key is of format:
	// 0x03<granteeAddressLen (1 Byte)><granteeAddress_Bytes><granterAddressLen (1 Byte)><granterAddress_Bytes>
	kv.AssertKeyAtLeastLength(key, 2)
	key = key[1:] // remove prefix key
	granteeAddrLen := key[0]
	kv.AssertKeyAtLeastLength(key, int(granteeAddrLen))
	key = key[1:]
	granteeAddr := key[:granteeAddrLen]
	kv.AssertKeyAtLeastLength(key, 1)
	key = key[granteeAddrLen:]
	granterAddrLen := int(key[0])
	key = key[1:]
	kv.AssertKeyLength(key, granterAddrLen)
	granterAddr := key

	return granteeAddr, granterAddr
}

// firstAddressFromGrantStoreKey parses the first address only
func firstAddressFromGrantStoreKey(key []byte) sdk.AccAddress {
	addrLen := key[0]
	return key[1 : 1+addrLen]
}
