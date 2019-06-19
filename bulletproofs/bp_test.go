package bulletproofs

import (
	"math/big"
	"testing"
)

/*
Test the FALSE case of ZK Range Proof scheme using Bulletproofs.
*/
func TestFalseBulletproofsZKRP(t *testing.T) {
	var (
		zkrp bp
	)
	_ = zkrp.Setup(0, 4294967296) // ITS BEING USED TO COMPUTE N

	x := new(big.Int).SetInt64(4294967296)

	proof, params, _ := zkrp.Prove(x)

	ok, _ := zkrp.Verify(proof, params)
	if ok != false {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}

/*
Test the TRUE case of ZK Range Proof scheme using Bulletproofs.
*/
func TestExtractedTrueBulletproofsZKRP(t *testing.T) {
	prover := new(bp)
	_ = prover.Setup(0, 4294967296)
	x := new(big.Int).SetInt64(65535)
	proof, params, _ := prover.Prove(x)

	verifier := new(bp)
	_ = verifier.Setup(0, 4294967296)
	ok, _ := verifier.Verify(proof, params)

	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}

/*
Test the TRUE case of ZK Range Proof scheme using Bulletproofs.
*/
func TestTrueBulletproofsZKRP(t *testing.T) {
	var zkrp bp
	_ = zkrp.Setup(0, 4294967296) // ITS BEING USED TO COMPUTE N

	x := new(big.Int).SetInt64(65535)
	proof, params, _ := zkrp.Prove(x)

	ok, _ := zkrp.Verify(proof, params)
	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}

func BenchmarkBulletproofs(b *testing.B) {
	var zkrp bp
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = zkrp.Setup(0, 4294967296) // ITS BEING USED TO COMPUTE N

		x := new(big.Int).SetInt64(4294967295)
		proof, params, _ := zkrp.Prove(x)
		ok, _ := zkrp.Verify(proof, params)

		if ok != true {
			b.Errorf("Assert failure: expected true, actual: %t", ok)
		}
	}
}
