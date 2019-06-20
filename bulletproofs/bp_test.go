package bulletproofs

import (
	"math/big"
	"testing"
)

/*
Test the TRUE case of ZK Range Proof scheme using Bulletproofs.
*/
//TODO: Make this test successful
//func TestExtractedFailBulletproofsZKRP(t *testing.T) {
//	params, _ := Setup(65536, 4294967296)
//
//	x := new(big.Int).SetInt64(65535)
//	proof, _ := Prove(x, params)
//
//	json, _ := proof.MarshalJSON()
//
//	proofForVerifier := new(ProofBP)
//	_ = proofForVerifier.UnmarshalJSON(json)
//
//	ok, _ := proofForVerifier.Verify()
//
//	if ok == true {
//		t.Errorf("Assert failure: expected false, actual: %t", ok)
//	}
//}

/*
Test the TRUE case of ZK Range Proof scheme using Bulletproofs.
*/
func TestExtractedTrueBulletproofsZKRP(t *testing.T) {
	params, _ := Setup(0, 4294967296)

	x := new(big.Int).SetInt64(65535)
	proof, _ := Prove(x, params)

	json, _ := proof.MarshalJSON()

	proofForVerifier := new(ProofBP)
	_ = proofForVerifier.UnmarshalJSON(json)

	ok, _ := proofForVerifier.Verify()

	if ok != true {
		t.Errorf("Assert failure: expected true, actual: %t", ok)
	}
}


//TODO: fix this for new interfaces, take out of normal test run
//func BenchmarkBulletproofs(b *testing.B) {
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		zkrp, _ := Setup(0, 4294967296) // ITS BEING USED TO COMPUTE N
//
//		x := new(big.Int).SetInt64(4294967295)
//		proof, params, _ := zkrp.Prove(x)
//		ok, _ := zkrp.Verify(proof, params)
//
//		if ok != true {
//			b.Errorf("Assert failure: expected true, actual: %t", ok)
//		}
//	}
//}
