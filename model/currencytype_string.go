// Code generated by "stringer -type=CurrencyType,CurveType"; DO NOT EDIT.

package model

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[Unspecified-0]
	_ = x[Bitcoin-1]
	_ = x[Ethereum-2]
	_ = x[Native-3]
	_ = x[Flexible-4]
}

const _CurrencyType_name = "UnspecifiedBitcoinEthereumNativeFlexible"

var _CurrencyType_index = [...]uint8{0, 11, 18, 26, 32, 40}

func (i CurrencyType) String() string {
	if i >= CurrencyType(len(_CurrencyType_index)-1) {
		return "CurrencyType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _CurrencyType_name[_CurrencyType_index[i]:_CurrencyType_index[i+1]]
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[Secp256k1-0]
	_ = x[NativeCurve-1]
}

const _CurveType_name = "Secp256k1NativeCurve"

var _CurveType_index = [...]uint8{0, 9, 20}

func (i CurveType) String() string {
	if i >= CurveType(len(_CurveType_index)-1) {
		return "CurveType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _CurveType_name[_CurveType_index[i]:_CurveType_index[i+1]]
}
