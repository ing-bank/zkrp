package intconversion

import "math/big"

/*
Read big integer in base 10 from string.
*/
func BigFromBase10(value string) *big.Int {
	i, _ := new(big.Int).SetString(value, 10)
	return i
}
