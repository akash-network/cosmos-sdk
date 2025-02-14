package keeper

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"cosmossdk.io/errors"
	"cosmossdk.io/store/prefix"
	storetypes "cosmossdk.io/store/types"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/cosmos/cosmos-sdk/x/authz"
)

var _ authz.QueryServer = Keeper{}

// Grants implements the Query/Grants gRPC method.
// It returns grants for a granter-grantee pair. If msg type URL is set, it returns grants only for that msg type.
func (k Keeper) Grants(ctx context.Context, req *authz.QueryGrantsRequest) (*authz.QueryGrantsResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "empty request")
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
		grant, found := k.getGrant(ctx, grantStoreKey(grantee, granter, req.MsgTypeUrl))
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
	key := grantStoreKey(grantee, granter, "")
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

	granter, err := k.authKeeper.AddressCodec().StringToBytes(req.Granter)
	if err != nil {
		return nil, err
	}

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	authzStore := prefix.NewStore(store, grantStoreKey(nil, granter, ""))

	grants, pageRes, err := query.GenericFilteredPaginate(k.cdc, authzStore, req.Pagination, func(key []byte, auth *authz.Grant) (*authz.GrantAuthorization, error) {
		auth1, err := auth.GetAuthorization()
		if err != nil {
			return nil, err
		}

		any, err := codectypes.NewAnyWithValue(auth1)
		if err != nil {
			return nil, status.Errorf(codes.Internal, err.Error())
		}

		grantee := firstAddressFromGrantStoreKey(key)
		return &authz.GrantAuthorization{
			Granter:       req.Granter,
			Grantee:       grantee.String(),
			Authorization: any,
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

// GranteeGrants implements the Query/GranteeGrants gRPC method.
func (k Keeper) GranteeGrants(ctx context.Context, req *authz.QueryGranteeGrantsRequest) (*authz.QueryGranteeGrantsResponse, error) {
	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "empty request")
	}

	grantee, err := k.authKeeper.AddressCodec().StringToBytes(req.Grantee)
	if err != nil {
		return nil, err
	}

	iter := storetypes.KVStorePrefixIterator(runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx)), granteeStoreKey(grantee, nil))
	defer func() {
		_ = iter.Close()
	}()

	if req.Pagination == nil {
		req.Pagination = &query.PageRequest{}
	}

	if req.Pagination.Limit == 0 {
		req.Pagination.Limit = query.DefaultLimit
	}

	var pageRes *query.PageResponse
	var grants []*authz.GrantAuthorization

	for ; iter.Valid(); iter.Next() {
		grantee, granter := parseGranteeStoreKey(iter.Key())

		var authorizations []*authz.GrantAuthorization

		store := prefix.NewStore(runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx)), GrantKey)

		authorizations, pageRes, err = query.GenericFilteredPaginate(k.cdc, store, req.Pagination, func(key []byte, auth *authz.Grant) (*authz.GrantAuthorization, error) {
			auth1, err := auth.GetAuthorization()
			if err != nil {
				return nil, err
			}

			authorizationAny, err := codectypes.NewAnyWithValue(auth1)
			if err != nil {
				return nil, status.Errorf(codes.Internal, err.Error())
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

		if err != nil {
			return nil, err
		}

		grants = append(grants, authorizations...)

		req.Pagination.Limit -= uint64(len(authorizations))
		if req.Pagination.Limit == 0 {
			break
		}
	}

	return &authz.QueryGranteeGrantsResponse{
		Grants:     grants,
		Pagination: pageRes,
	}, nil
}
