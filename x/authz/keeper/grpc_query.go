package keeper

import (
	"context"
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"hash/crc32"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"cosmossdk.io/errors"
	"cosmossdk.io/store/prefix"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/cosmos/cosmos-sdk/x/authz"
	"github.com/cosmos/cosmos-sdk/x/authz/keeper/keys"
)

var _ authz.QueryServer = Keeper{}

var (
	errBreak = stderrors.New("break")
)

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
	grantsStore := prefix.NewStore(store, key)

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
	authzStore := prefix.NewStore(store, keys.GrantStoreKey(nil, granter, ""))

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

func decodePaginationRequest(req *query.PageRequest) (*query.PageRequest, *query.PageRequest, error) {
	granteeReq := &query.PageRequest{}
	granterReq := &query.PageRequest{}

	if req != nil {
		granteeReq.Limit = req.Limit
		granterReq.Limit = req.Limit

		if len(req.Key) > 0 {
			key := req.Key

			if len(key) < 5 {
				return nil, nil, fmt.Errorf("%w: invalid key length", query.ErrInvalidPaginationKey)
			}

			expectedChecksum := binary.BigEndian.Uint32(key)

			key = key[4:]

			checksum := crc32.ChecksumIEEE(key)

			if expectedChecksum != checksum {
				return nil, nil, fmt.Errorf("%w: invalid checksum, 0x%08x != 0x%08x", query.ErrInvalidPaginationKey, expectedChecksum, checksum)
			}

			for len(key) > 0 {
				if len(key) < 2 {
					return nil, nil, fmt.Errorf("%w: invalid key length", query.ErrInvalidPaginationKey)
				}
				keyType := key[0]
				key = key[1:]
				prefixLength := int(key[0])
				key = key[1:]

				if len(key) < prefixLength {
					return nil, nil, fmt.Errorf("%w: invalid key length", query.ErrInvalidPaginationKey)
				}

				switch keyType {
				case 1:
					granteeReq.Key = key[:prefixLength]
				case 2:
					granterReq.Key = key[:prefixLength]
				default:
					return nil, nil, fmt.Errorf("%w: invalid key type", query.ErrInvalidPaginationKey)
				}

				key = key[prefixLength:]
			}
		}
	}

	if granteeReq.Limit == 0 {
		granteeReq.Limit = query.DefaultLimit
		granterReq.Limit = query.DefaultLimit
	}

	return granteeReq, granterReq, nil
}

func encodePaginationResponse(grantee *query.PageResponse, granter *query.PageResponse) []byte {
	if grantee == nil && granter == nil {
		return nil
	}

	encLen := 4

	if grantee != nil && grantee.NextKey != nil {
		encLen += 1 + 1 + len(grantee.NextKey)
	}

	if granter != nil && granter.NextKey != nil {
		encLen += 1 + 1 + len(granter.NextKey)
	}

	buf := make([]byte, encLen)

	data := buf[4:]
	if grantee != nil && grantee.NextKey != nil {
		data[0] = 1

		dLen := uint8(len(grantee.NextKey))
		data[1] = dLen
		data = data[2:]
		copy(data, grantee.NextKey)
		data = data[dLen:]
	}

	if granter != nil && granter.NextKey != nil {
		data[0] = 2

		dLen := uint8(len(granter.NextKey))
		data[1] = dLen
		data = data[2:]
		copy(data, granter.NextKey)
		data = data[dLen:]
	}

	checksum := crc32.ChecksumIEEE(data)
	binary.BigEndian.PutUint32(buf, checksum)

	return buf
}

// GranteeGrants implements the Query/GranteeGrants gRPC method.
func (k Keeper) GranteeGrants(ctx context.Context, req *authz.QueryGranteeGrantsRequest) (*authz.QueryGranteeGrantsResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "empty request")
	}

	granteePg, granterPg, err := decodePaginationRequest(req.Pagination)
	if err != nil {
		return nil, err
	}

	grantee, err := k.authKeeper.AddressCodec().StringToBytes(req.Grantee)
	if err != nil {
		return nil, err
	}

	var grants []*authz.GrantAuthorization

	var granteePgResp *query.PageResponse
	var granterPgResp *query.PageResponse

	gStore := prefix.NewStore(runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx)), keys.GranteeStoreKey(grantee, nil))
	granteePgResp, err = query.FilteredPaginate(gStore, granteePg, func(key []byte, value []byte, accumulate bool) (bool, error) {
		grantee, granter := keys.ParseGranteeStoreKey(key)

		store := prefix.NewStore(runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx)), keys.GrantKey)

		var er error
		var res []*authz.GrantAuthorization

		res, granterPgResp, er = query.GenericFilteredPaginate(k.cdc, store, granterPg, func(key []byte, auth *authz.Grant) (*authz.GrantAuthorization, error) {
			auth1, er := auth.GetAuthorization()
			if err != nil {
				return nil, er
			}

			authorizationAny, er := codectypes.NewAnyWithValue(auth1)
			if er != nil {
				return nil, status.Errorf(codes.Internal, er.Error())
			}

			return &authz.GrantAuthorization{
				Authorization: authorizationAny,
				Expiration:    auth.Expiration,
				Granter:       granter.String(),
				Grantee:       grantee.String(),
			}, nil
		}, func() *authz.Grant {
			return &authz.Grant{}
		})

		if er != nil {
			return false, err
		}

		grants = append(grants, res...)
		granteePg.Limit -= uint64(len(res))
		granterPg.Limit -= uint64(len(res))

		if granteePg.Limit == 0 {
			return true, errBreak
		}

		return true, nil
	})

	if err != nil && !stderrors.Is(err, errBreak) {
		return nil, err
	}

	var pageRes *query.PageResponse
	if key := encodePaginationResponse(granteePgResp, granterPgResp); len(key) > 0 {
		pageRes = &query.PageResponse{
			NextKey: key,
		}
	}

	return &authz.QueryGranteeGrantsResponse{
		Grants:     grants,
		Pagination: pageRes,
	}, nil
}
