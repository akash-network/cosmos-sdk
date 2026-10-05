package types

import (
	"fmt"

	"cosmossdk.io/math"
)

var (
	// denomUnits contains a mapping of denomination mapped to their respective unit
	// multipliers (e.g. 1atom = 10^-6uatom).
	denomUnits = map[string]math.LegacyDec{}

	//// baseDenom is the denom of smallest unit registered
	//baseDenom string

	// baseDenom is the denom of smallest unit registered
	baseDenoms = map[string]string{}
)

// RegisterDenom registers a denomination with a corresponding unit. If the
// denomination is already registered, an error will be returned.
func RegisterDenom(denom string, unit math.LegacyDec) error {
	if err := ValidateDenom(denom); err != nil {
		return err
	}

	if _, ok := denomUnits[denom]; ok {
		return fmt.Errorf("denom %s already registered", denom)
	}

	denomUnits[denom] = unit

	coreDenom := denom[len(denom)-3:]
	base, exists := baseDenoms[coreDenom]
	if !exists || unit.LT(denomUnits[base]) {
		baseDenoms[coreDenom] = denom
	}

	return nil
}

// GetDenomUnit returns a unit for a given denomination if it exists. A boolean
// is returned if the denomination is registered.
func GetDenomUnit(denom string) (math.LegacyDec, bool) {
	if err := ValidateDenom(denom); err != nil {
		return math.LegacyZeroDec(), false
	}

	unit, ok := denomUnits[denom]
	if !ok {
		return math.LegacyZeroDec(), false
	}

	return unit, true
}

// GetBaseDenom returns the denom of smallest unit registered
func GetBaseDenom(denom string) (string, error) {
	coreDenom := denom[len(denom)-3:]
	base, exists := baseDenoms[coreDenom]
	if !exists {
		return "", fmt.Errorf("no denom is registered")
	}

	return base, nil
}

// ConvertCoin attempts to convert a coin to a given denomination. If the given
// denomination is invalid or if neither denomination is registered, an error
// is returned.
func ConvertCoin(coin Coin, denom string) (Coin, error) {
	if err := ValidateDenom(denom); err != nil {
		return Coin{}, err
	}

	srcUnit, ok := GetDenomUnit(coin.Denom)
	if !ok {
		return Coin{}, fmt.Errorf("source denom not registered: %s", coin.Denom)
	}

	dstUnit, ok := GetDenomUnit(denom)
	if !ok {
		return Coin{}, fmt.Errorf("destination denom not registered: %s", denom)
	}

	if srcUnit.Equal(dstUnit) {
		return NewCoin(denom, coin.Amount), nil
	}

	return NewCoin(denom, math.LegacyNewDecFromInt(coin.Amount).Mul(srcUnit).Quo(dstUnit).TruncateInt()), nil
}

// ConvertDecCoin attempts to convert a decimal coin to a given denomination. If the given
// denomination is invalid or if neither denomination is registered, an error
// is returned.
func ConvertDecCoin(coin DecCoin, denom string) (DecCoin, error) {
	if err := ValidateDenom(denom); err != nil {
		return DecCoin{}, err
	}

	srcUnit, ok := GetDenomUnit(coin.Denom)
	if !ok {
		return DecCoin{}, fmt.Errorf("source denom not registered: %s", coin.Denom)
	}

	dstUnit, ok := GetDenomUnit(denom)
	if !ok {
		return DecCoin{}, fmt.Errorf("destination denom not registered: %s", denom)
	}

	if srcUnit.Equal(dstUnit) {
		return NewDecCoinFromDec(denom, coin.Amount), nil
	}

	return NewDecCoinFromDec(denom, coin.Amount.Mul(srcUnit).Quo(dstUnit)), nil
}

// NormalizeCoin try to convert a coin to the smallest unit registered,
// returns original one if failed.
func NormalizeCoin(coin Coin) Coin {
	base, err := GetBaseDenom(coin.Denom)
	if err != nil {
		return coin
	}
	newCoin, err := ConvertCoin(coin, base)
	if err != nil {
		return coin
	}
	return newCoin
}

// NormalizeDecCoin try to convert a decimal coin to the smallest unit registered,
// returns original one if failed.
func NormalizeDecCoin(coin DecCoin) DecCoin {
	base, err := GetBaseDenom(coin.Denom)
	if err != nil {
		return coin
	}
	newCoin, err := ConvertDecCoin(coin, base)
	if err != nil {
		return coin
	}
	return newCoin
}

// NormalizeCoins normalize and truncate a list of decimal coins
func NormalizeCoins(coins []DecCoin) Coins {
	if coins == nil {
		return nil
	}
	result := make([]Coin, 0, len(coins))

	for _, coin := range coins {
		newCoin, _ := NormalizeDecCoin(coin).TruncateDecimal()
		result = append(result, newCoin)
	}

	return result
}
