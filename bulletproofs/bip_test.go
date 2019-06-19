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
		zkip bip
		a    []*big.Int
		b    []*big.Int
	)
	c := new(big.Int).SetInt64(142)
	_, _ = zkip.Setup(nil, nil, nil, c, 4)

	a = make([]*big.Int, zkip.N)
	a[0] = new(big.Int).SetInt64(2)
	a[1] = new(big.Int).SetInt64(-1)
	a[2] = new(big.Int).SetInt64(10)
	a[3] = new(big.Int).SetInt64(6)
	b = make([]*big.Int, zkip.N)
	b[0] = new(big.Int).SetInt64(1)
	b[1] = new(big.Int).SetInt64(2)
	b[2] = new(big.Int).SetInt64(10)
	b[3] = new(big.Int).SetInt64(7)
	commit := commitInnerProduct(zkip.Gg, zkip.Hh, a, b)

	proof, _ := zkip.Prove(a, b, commit)
	ok, _ := zkip.Verify(proof)
	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}
