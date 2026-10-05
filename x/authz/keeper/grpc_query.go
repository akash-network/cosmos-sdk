package keeper

import (
	"context"
	"encoding/binary"
	"hash/crc32"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"cosmossdk.io/errors"
	prefixstore "cosmossdk.io/store/prefix"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/cosmos/cosmos-sdk/x/authz/keeper/keys"
)

var _ authz.QueryServer = Keeper{}

// Grants implements the Query/Grants gRPC method.
// It returns grants for a granter-grantee pair. If msg type URL is set, it returns grants only for that msg type.
func (k Keeper) Grants(ctx context.Context, req *authz.QueryGrantsRequest) (*authz.QueryGrantsResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "empty request")
	}

	if req.Pagination == nil {
		req.Pagination = &query.PageRequest{}
	}

	if req.Pagination.Limit == 0 {
		req.Pagination.Limit = query.DefaultLimit
	}

	granter, err := k.authKeeper.AddressCodec().StringToBytes(req.Granter)
	if err != nil {
		return nil, err
	}

	grantee, err := k.authKeeper.AddressCodec().StringToBytes(req.Grantee)
	if err != nil {
		return nil, err
	}

	if req.MsgTypeUrl != "" {
		grant, found := k.getGrant(ctx, keys.GrantStoreKey(grantee, granter, req.MsgTypeUrl))
		if !found {
			return nil, errors.Wrapf(authz.ErrNoAuthorizationFound, "authorization not found for %s type", req.MsgTypeUrl)
		}

		authorization, err := grant.GetAuthorization()
		if err != nil {
			return nil, err
		}

		authorizationAny, err := codectypes.NewAnyWithValue(authorization)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		return &authz.QueryGrantsResponse{
			Grants: []*authz.Grant{{
				Authorization: authorizationAny,
				Expiration:    grant.Expiration,
			}},
		}, nil
	}

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	key := keys.GrantStoreKey(grantee, granter, "")
	grantsStore := prefixstore.NewStore(store, key)

	authorizations, pageRes, err := query.GenericFilteredPaginate(k.cdc, grantsStore, req.Pagination, func(key []byte, auth *authz.Grant) (*authz.Grant, error) {
		auth1, err := auth.GetAuthorization()
		if err != nil {
			return nil, err
		}

		authorizationAny, err := codectypes.NewAnyWithValue(auth1)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}
		return &authz.Grant{
			Authorization: authorizationAny,
			Expiration:    auth.Expiration,
		}, nil
	}, func() *authz.Grant {
		return &authz.Grant{}
	})
	if err != nil {
		return nil, err
	}

	return &authz.QueryGrantsResponse{
		Grants:     authorizations,
		Pagination: pageRes,
	}, nil
}

// GranterGrants implements the Query/GranterGrants gRPC method.
func (k Keeper) GranterGrants(ctx context.Context, req *authz.QueryGranterGrantsRequest) (*authz.QueryGranterGrantsResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "empty request")
	}

	if req.Pagination == nil {
		req.Pagination = &query.PageRequest{}
	}

	if req.Pagination.Limit == 0 {
		req.Pagination.Limit = query.DefaultLimit
	}

	granter, err := k.authKeeper.AddressCodec().StringToBytes(req.Granter)
	if err != nil {
		return nil, err
	}

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	authzStore := prefixstore.NewStore(store, keys.GrantStoreKey(nil, granter, ""))

	grants, pageRes, err := query.GenericFilteredPaginate(k.cdc, authzStore, req.Pagination, func(key []byte, auth *authz.Grant) (*authz.GrantAuthorization, error) {
		auth1, err := auth.GetAuthorization()
		if err != nil {
			return nil, err
		}

		authzVal, err := codectypes.NewAnyWithValue(auth1)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}

		grantee := keys.FirstAddressFromGrantStoreKey(key)
		return &authz.GrantAuthorization{
			Granter:       req.Granter,
			Grantee:       grantee.String(),
			Authorization: authzVal,
			Expiration:    auth.Expiration,
		}, nil
	}, func() *authz.Grant {
		return &authz.Grant{}
	})
	if err != nil {
		return nil, err
	}

	return &authz.QueryGranterGrantsResponse{
		Grants:     grants,
		Pagination: pageRes,
	}, nil
}

// decodePaginationKey decodes a pagination key into a prefix and primary key or returns an error if the key is invalid.
func decodePaginationKey(key []byte) ([]byte, []byte, error) {
	var prefix []byte
	var pKey []byte

	if len(key) > 0 {
		if len(key) < 5 {
			return nil, nil, errors.Wrapf(query.ErrInvalidPaginationKey, "invalid key length")
		}

		expectedChecksum := binary.BigEndian.Uint32(key)

		key = key[4:]

		checksum := crc32.ChecksumIEEE(key)

		if expectedChecksum != checksum {
			return nil, nil, errors.Wrapf(query.ErrInvalidPaginationKey, "invalid checksum, 0x%08x != 0x%08x", expectedChecksum, checksum)
		}

		for len(key) > 0 {
			if len(key) < 2 {
				return nil, nil, errors.Wrapf(query.ErrInvalidPaginationKey, "invalid key length")
			}
			keyType := key[0]
			key = key[1:]
			prefixLength := int(key[0])
			key = key[1:]

			if len(key) < prefixLength {
				return nil, nil, errors.Wrapf(query.ErrInvalidPaginationKey, "invalid key length")
			}

			switch keyType {
			case 1:
				prefix = make([]byte, prefixLength)
				copy(prefix, key[:prefixLength])
			case 2:
				pKey = make([]byte, prefixLength)
				copy(pKey, key[:prefixLength])
			default:
				return nil, nil, errors.Wrapf(query.ErrInvalidPaginationKey, "invalid key type")
			}

			key = key[prefixLength:]
		}
	}

	return prefix, pKey, nil
}

// encodePaginationKey creates a unique byte key by encoding a prefix and key with a checksum for validation.
// Returns nil if both prefix and key inputs are nil.
func encodePaginationKey(prefix []byte, key []byte) []byte {
	if prefix == nil && key == nil {
		return nil
	}

	// checksum
	encLen := 4 + 1 + 1 + 1 + 1 + len(prefix) + len(key)

	buf := make([]byte, encLen)

	data := buf[4:]

	data[0] = 1
	dLen := uint8(len(prefix))
	data[1] = dLen
	data = data[2:]
	copy(data, prefix)
	data = data[dLen:]

	data[0] = 2

	dLen = uint8(len(key))
	data[1] = dLen
	data = data[2:]
	copy(data, key)
	data = data[dLen:]

	checksum := crc32.ChecksumIEEE(buf[4:])
	binary.BigEndian.PutUint32(buf, checksum)

	return buf
}

// GranteeGrants implements the Query/GranteeGrants gRPC method.
func (k Keeper) GranteeGrants(ctx context.Context, req *authz.QueryGranteeGrantsRequest) (*authz.QueryGranteeGrantsResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "empty request")
	}

	if req.Pagination == nil {
		req.Pagination = &query.PageRequest{}
	}

	if req.Pagination.Limit == 0 {
		req.Pagination.Limit = query.DefaultLimit
	}

	storePrefix, pKey, err := decodePaginationKey(req.Pagination.Key)
	if err != nil {
		return nil, err
	}

	if len(storePrefix) == 0 {
		storePrefix = keys.GranteeGranterKey
		if req.Grantee != "" {
			grantee, err := k.authKeeper.AddressCodec().StringToBytes(req.Grantee)
			if err != nil {
				return nil, err
			}

			storePrefix = keys.GranteeGranterStoreKey(grantee, nil, "")
		}
	} else {
		req.Pagination.Key = pKey
	}

	var grants []*authz.GrantAuthorization

	gStore := prefixstore.NewStore(runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx)), storePrefix)

	pageRes, err := query.FilteredPaginate(gStore, req.Pagination, func(key []byte, value []byte, accumulate bool) (bool, error) {
		grantee, granter, msgTypeUrl := keys.ParseGranteeGranterStoreKey(append(storePrefix, key...))

		grant, found := k.getGrant(ctx, keys.GrantStoreKey(grantee, granter, msgTypeUrl))
		if !found {
			return false, nil
		}

		auth1, er := grant.GetAuthorization()
		if er != nil {
			return false, er
		}

		authorizationAny, er := codectypes.NewAnyWithValue(auth1)
		if er != nil {
			return false, status.Errorf(codes.Internal, er.Error())
		}

		if accumulate {
			grants = append(grants, &authz.GrantAuthorization{
				Authorization: authorizationAny,
				Expiration:    grant.Expiration,
				Granter:       granter.String(),
				Grantee:       grantee.String(),
			})
		}

		return true, nil
	})
	if err != nil {
		return nil, err
	}

	if len(pageRes.NextKey) > 0 {
		pageRes.NextKey = encodePaginationKey(storePrefix, pageRes.NextKey)
	}

	return &authz.QueryGranteeGrantsResponse{
		Grants:     grants,
		Pagination: pageRes,
	}, nil
}
