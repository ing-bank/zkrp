package bulletproofs

import (
	"math/big"
)

/*
*/
type bprp struct {
	A int64
	B int64
	BP1 bp
	BP2 bp
}

/*
*/
type ProofBPRP struct {
	P1 ProofBP
	P2 ProofBP
}

/*
*/
func (zkrp *bprp) Setup(a, b int64) error {
	zkrp.A = a
	zkrp.B = b
	_ = zkrp.BP1.Setup(0, 4294967296)
	_ = zkrp.BP2.Setup(0, 4294967296)
	return nil
}

/*
*/
func (zkrp *bprp) Prove(secret *big.Int) (ProofBPRP, error) {
	var (
		proof ProofBPRP
	)
        // x - b + 2^N
	p2 := new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(32), nil)
        xb := new(big.Int).Sub(secret, new(big.Int).SetInt64(zkrp.B))
        xb.Add(xb, p2)
	proof.P1, _ = zkrp.BP1.Prove(xb)

	xa := new(big.Int).Sub(secret, new(big.Int).SetInt64(zkrp.A))
	proof.P2, _ = zkrp.BP2.Prove(xa)

	return proof, nil
}

/*
*/
func (zkrp *bprp) Verify(proof ProofBPRP) (bool, error) {
	ok1, _ := zkrp.BP1.Verify(proof.P1)
	ok2, _ := zkrp.BP2.Verify(proof.P2)

	return ok1 && ok2, nil
}
