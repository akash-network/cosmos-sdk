package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	v2 "github.com/cosmos/cosmos-sdk/x/authz/migrations/v2"
)

// Migrator is a struct for handling in-place store migrations.
type Migrator struct {
	keeper Keeper
}

// NewMigrator returns a new Migrator.
func NewMigrator(keeper Keeper) Migrator {
	return Migrator{keeper: keeper}
}

// Migrate2to3 migrates from version 2 to 3.
func (m Migrator) Migrate2to3(ctx sdk.Context) error {
	return v2.MigrateStore(ctx, m.keeper.storeService, m.keeper.cdc)
}
