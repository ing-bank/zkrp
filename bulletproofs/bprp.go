/*
 * Copyright (C) 2019 ING BANK N.V.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package bulletproofs

import (
    "math/big"
)

/*
bprp structure contains 2 BulletProofs in order to allow computation of
generic Range Proofs, for any interval [A, B).
*/
type bprp struct {
    A   int64
    B   int64
    BP1 BulletProofSetupParams
    BP2 BulletProofSetupParams
}

/*
ProofBPRP stores the generic ZKRP.
*/
type ProofBPRP struct {
    P1 BulletProof
    P2 BulletProof
}

/*
SetupGeneric is responsible for calling the Setup algorithm for each
BulletProof.
*/
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

/*
BulletProof only works for interval in the format [0, 2^N). In order to
allow generic intervals in the format [A, B) it is necessary to use 2
BulletProofs, as explained in Section 4.3 from the following paper:
https://infoscience.epfl.ch/record/128718/files/CCS08.pdf
*/
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

/*
Verify call the Verification algorithm for each BulletProof argument.
*/
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
