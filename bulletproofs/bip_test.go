package bulletproofs

import (
	"math/big"
	"testing"
)

/*
Test Inner Product argument where <a,b>=c.
*/
func TestInnerProduct(t *testing.T) {
	var (
		innerProductParams InnerProductParams
		a                  []*big.Int
		b                  []*big.Int
	)
	c := new(big.Int).SetInt64(142)
	innerProductParams, _ = setupInnerProduct(nil, nil, nil, c, 4)

	a = make([]*big.Int, innerProductParams.N)
	a[0] = new(big.Int).SetInt64(2)
	a[1] = new(big.Int).SetInt64(-1)
	a[2] = new(big.Int).SetInt64(10)
	a[3] = new(big.Int).SetInt64(6)
	b = make([]*big.Int, innerProductParams.N)
	b[0] = new(big.Int).SetInt64(1)
	b[1] = new(big.Int).SetInt64(2)
	b[2] = new(big.Int).SetInt64(10)
	b[3] = new(big.Int).SetInt64(7)
	commit := commitInnerProduct(innerProductParams.Gg, innerProductParams.Hh, a, b)

	proof, _ := proveInnerProduct(a, b, commit, innerProductParams)
	ok, _ := proof.Verify()
	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}
