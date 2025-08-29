package keeper

import (
	"context"

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

	storePrefix := keys.GranteeGranterKey

	if len(req.Pagination.Key) == 0 {
		grantee, err := k.authKeeper.AddressCodec().StringToBytes(req.Grantee)
		if err != nil {
			return nil, err
		}

		storePrefix = keys.GranteeGranterStoreKey(grantee, nil, "")
	}

	var grants []*authz.GrantAuthorization

	gStore := prefix.NewStore(runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx)), storePrefix)

	pageRes, err := query.FilteredPaginate(gStore, req.Pagination, func(key []byte, value []byte, accumulate bool) (bool, error) {
		if !accumulate {
			return false, nil
		}

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

		grants = append(grants, &authz.GrantAuthorization{
			Authorization: authorizationAny,
			Expiration:    grant.Expiration,
			Granter:       granter.String(),
			Grantee:       grantee.String(),
		})

		return true, nil
	})

	if err != nil {
		return nil, err
	}

	return &authz.QueryGranteeGrantsResponse{
		Grants:     grants,
		Pagination: pageRes,
	}, nil
}
