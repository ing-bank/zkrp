package bulletproofs

import (
	"math/big"
)

/*
 */
type bprp struct {
	A   int64
	B   int64
	BP1 BulletProofSetupParams
	BP2 BulletProofSetupParams
}

type ProofBPRP struct {
	P1 BulletProof
	P2 BulletProof
}

func SetupGeneric(a, b int64) (*bprp, error) {
	params := new(bprp)
	params.A = a
	params.B = b
	var errBp1, errBp2 error
	params.BP1, errBp1 = Setup(MAX_RANGE_END)
	if errBp1 != nil {
		return nil, errBp1
	}
	params.BP2, errBp2 = Setup(MAX_RANGE_END)
	if errBp2 != nil {
		return nil, errBp2
	}
	return params, nil
}

func ProveGeneric(secret *big.Int, params *bprp) (ProofBPRP, error) {
	var proof ProofBPRP

	// x - b + 2^N
	p2 := new(big.Int).SetInt64(MAX_RANGE_END)
	xb := new(big.Int).Sub(secret, new(big.Int).SetInt64(params.B))
	xb.Add(xb, p2)

	var err1 error
	proof.P1, err1 = Prove(xb, params.BP1)
	if err1 != nil {
		return proof, err1
	}

	xa := new(big.Int).Sub(secret, new(big.Int).SetInt64(params.A))
	var err2 error
	proof.P2, err2 = Prove(xa, params.BP2)
	if err2 != nil {
		return proof, err2
	}

	return proof, nil
}

func (proof ProofBPRP) Verify() (bool, error) {
	ok1, err1 := proof.P1.Verify()
	if !ok1 {
		return false, err1
	}
	ok2, err2 := proof.P2.Verify()
	if !ok2 {
		return false, err2
	}

	return ok1 && ok2, nil
}
