package bulletproofs

import (
	"math/big"
	"testing"
)

/*
Test Inner Product argument.
*/
func TestInnerProduct(t *testing.T) {
	var (
		zkrp bp
		zkip bip
		a    []*big.Int
		b    []*big.Int
	)
	// TODO:
	// Review if it is the best way, since we maybe could use the
	// inner product independently of the range proof.
	_ = zkrp.Setup(0, 16)

	a = make([]*big.Int, zkrp.N)
	a[0] = new(big.Int).SetInt64(2)
	a[1] = new(big.Int).SetInt64(-1)
	a[2] = new(big.Int).SetInt64(10)
	a[3] = new(big.Int).SetInt64(6)
	b = make([]*big.Int, zkrp.N)
	b[0] = new(big.Int).SetInt64(1)
	b[1] = new(big.Int).SetInt64(2)
	b[2] = new(big.Int).SetInt64(10)
	b[3] = new(big.Int).SetInt64(7)
	c := new(big.Int).SetInt64(142)
	commit := commitInnerProduct(zkrp.Gg, zkrp.Hh, a, b)
	_, _ = zkip.Setup(zkrp.H, zkrp.Gg, zkrp.Hh, c)

	proof, _ := zkip.Prove(a, b, commit)
	ok, _ := zkip.Verify(proof)
	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}
