package bulletproofs

import (
	"math/big"
	"testing"
)

/*
Test the TRUE case of Generic ZK Range Proof scheme using Bulletproofs.
*/
func TestTrueGenericBulletproofsZKRP(t *testing.T) {
        var (
                zkrp bprp
        )
        //A = 18
        //B = 200
        //X = 19 
        secret, _ := new(big.Int).SetString("19", 10)

        _ = zkrp.Setup(18, 200) // ITS BEING USED TO COMPUTE N
        proof, _ := zkrp.Prove(secret)
        ok, _ := zkrp.Verify(proof)

        if ok != true {
                t.Errorf("Assert failure: expected true, actual: %t", ok)
        }
}

/*
Test the FALSE case of Generic ZK Range Proof scheme using Bulletproofs.
*/
func TestFalseGenericBulletproofsZKRP(t *testing.T) {
        var (
                zkrp bprp
        )
        //A = 18
        //B = 200
        //X = 201
        secret, _ := new(big.Int).SetString("201", 10)

        _ = zkrp.Setup(18, 200) // ITS BEING USED TO COMPUTE N
        proof, _ := zkrp.Prove(secret)
        ok, _ := zkrp.Verify(proof)

        if ok != false {
                t.Errorf("Assert failure: expected false, actual: %t", ok)
        }
}

