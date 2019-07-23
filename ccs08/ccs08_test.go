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

package ccs08

import (
    "crypto/rand"
    "math/big"
    "testing"

    "github.com/ing-bank/zkrp/crypto/bn256"
    . "github.com/ing-bank/zkrp/util"
    "github.com/ing-bank/zkrp/util/bn"
    "github.com/ing-bank/zkrp/util/intconversion"
)

/*
Tests decomposion into bits.
*/
func TestDecompose(t *testing.T) {
    h := intconversion.BigFromBase10("925")
    decx, _ := Decompose(h, 10, 3)
    if decx[0] != 5 || decx[1] != 2 || decx[2] != 9 {
        t.Errorf("Assert failure: expected true, actual: %d", decx)
    }
}

/*
Tests Inversion on G1 group.
*/
func TestNegScalarBaseMulG1(t *testing.T) {
    b, _ := rand.Int(rand.Reader, bn256.Order)
    pb := new(bn256.G1).ScalarBaseMult(b)
    mb := bn.Sub(new(big.Int).SetInt64(0), b)
    mpb := new(bn256.G1).ScalarBaseMult(mb)
    a := new(bn256.G1).Add(pb, mpb)
    aBytes := a.Marshal()
    for i := 0; i < len(aBytes)-1; i++ {
        if aBytes[i] != 0 {
            t.Errorf("Assert failure: expected true, actual: %t", aBytes[i] == 0)
        }
    }
    if aBytes[len(aBytes)-1] != 1 {
        t.Errorf("Assert failure: expected true, actual: %t", aBytes[len(aBytes)-1] == 1)
    }
}

/*
Tests Inversion on G2 group.
*/
func TestNegScalarBaseMulG2(t *testing.T) {
    b, _ := rand.Int(rand.Reader, bn256.Order)
    pb := new(bn256.G2).ScalarBaseMult(b)
    mb := bn.Sub(new(big.Int).SetInt64(0), b)
    mpb := new(bn256.G2).ScalarBaseMult(mb)
    a := new(bn256.G2).Add(pb, mpb)
    if a.IsZero() != true {
        t.Errorf("Assert failure: expected true, actual: %t", a.IsZero())
    }
}

/*
Tests Inversion on GFp12 finite field.
*/
func TestInvertGFp12(t *testing.T) {
    b, _ := rand.Int(rand.Reader, bn256.Order)
    c, _ := rand.Int(rand.Reader, bn256.Order)

    pb, _ := new(bn256.G1).Unmarshal(new(bn256.G1).ScalarBaseMult(b).Marshal())
    qc, _ := new(bn256.G2).Unmarshal(new(bn256.G2).ScalarBaseMult(c).Marshal())

    k1 := bn256.Pair(pb, qc)
    k2 := new(bn256.GT).Invert(k1)
    k3 := new(bn256.GT).Add(k1, k2)
    if k3.IsOne() != true {
        t.Errorf("Assert failure: expected true, actual: %t", k3.IsOne())
    }
}

/*
Tests the ZK Range Proof building block, where the interval is [0, U^L).
*/
func TestZKRP_UL(t *testing.T) {
    var (
        r *big.Int
    )
    p, _ := SetupUL(10, 5)
    r, _ = rand.Int(rand.Reader, bn256.Order)
    proof_out, _ := ProveUL(new(big.Int).SetInt64(42176), r, p)
    result, _ := VerifyUL(&proof_out, &p)
    if result != true {
        t.Errorf("Assert failure: expected true, actual: %t", result)
    }
}

/*
Tests if the SetupInnerProduct algorithm is rejecting wrong input as expected.
*/
func TestZKRPSetupInput(t *testing.T) {
    var (
        zkrp ccs08
    )
    e := zkrp.Setup(1900, 1899)
    result := e.Error() != "a must be less than or equal to b"
    if result {
        t.Errorf("Assert failure: expected true, actual: %t", result)
    }
}

/*
Tests the ZK Set Membership (CCS08) protocol.
*/
func TestZKSet(t *testing.T) {
    var (
        r *big.Int
        s []int64
    )
    s = make([]int64, 4)
    s[0] = 12
    s[1] = 42
    s[2] = 61
    s[3] = 71
    p, _ := SetupSet(s)
    r, _ = rand.Int(rand.Reader, bn256.Order)
    proof_out, _ := ProveSet(12, r, p)
    result, _ := VerifySet(&proof_out, &p)
    if result != true {
        t.Errorf("Assert failure: expected true, actual: %t", result)
    }
}

/*
Tests the entire ZK Range Proof (CCS08) protocol.
*/
func TestZKRP(t *testing.T) {
    var (
        result bool
        zkrp   ccs08
    )
    zkrp.Setup(347184000, 599644800)
    zkrp.x = new(big.Int).SetInt64(419835123)
    zkrp.r, _ = rand.Int(rand.Reader, bn256.Order)
    e := zkrp.Prove()
    if e != nil {
        t.Errorf("Error while proving ZKRP: %s", e.Error())
    }
    result, _ = zkrp.Verify()
    if result != true {
        t.Errorf("Assert failure: expected true, actual: %t", result)
    }
}
