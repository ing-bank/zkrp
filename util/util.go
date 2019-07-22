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

package util

import (
    "crypto/sha256"
    "math/big"

    "github.com/ing-bank/zkrp/crypto/bn256"
    "github.com/ing-bank/zkrp/crypto/p256"
    "github.com/ing-bank/zkrp/util/bn"
    "github.com/ing-bank/zkrp/util/byteconversion"
)

// Constants that are going to be used frequently, then we just need to compute them once.
var (
    G1 = new(bn256.G1).ScalarBaseMult(new(big.Int).SetInt64(1))
    G2 = new(bn256.G2).ScalarBaseMult(new(big.Int).SetInt64(1))
    E  = bn256.Pair(G1, G2)
)

/*
Decompose receives as input a bigint x and outputs an array of integers such that
x = sum(xi.u^i), i.e. it returns the decomposition of x into base u.
*/
func Decompose(x *big.Int, u int64, l int64) ([]int64, error) {
    var (
        result []int64
        i      int64
    )
    result = make([]int64, l)
    i = 0
    for i < l {
        result[i] = bn.Mod(x, new(big.Int).SetInt64(u)).Int64()
        x = new(big.Int).Div(x, new(big.Int).SetInt64(u))
        i = i + 1
    }
    return result, nil
}

/*
Commit method corresponds to the Pedersen commitment scheme. Namely, given input
message x, and randomness r, it outputs g^x.h^r.
*/
func Commit(x, r *big.Int, h *bn256.G2) (*bn256.G2, error) {
    var C = new(bn256.G2).ScalarBaseMult(x)
    C.Add(C, new(bn256.G2).ScalarMult(h, r))
    return C, nil
}

/*
CommitG1 method corresponds to the Pedersen commitment scheme. Namely, given input
message x, and randomness r, it outputs g^x.h^r.
*/
func CommitG1(x, r *big.Int, h *p256.P256) (*p256.P256, error) {
    var C = new(p256.P256).ScalarBaseMult(x)
    Hr := new(p256.P256).ScalarMult(h, r)
    C.Add(C, Hr)
    return C, nil
}

/*
HashSet is responsible for the computing a Zp element given elements from GT and G2.
*/
func HashSet(a *bn256.GT, D *bn256.G2) (*big.Int, error) {
    digest := sha256.New()
    digest.Write([]byte(a.String()))
    digest.Write([]byte(D.String()))
    output := digest.Sum(nil)
    tmp := output[0:]
    return byteconversion.FromByteArray(tmp)
}

/*
Hash is responsible for the computing a Zp element given elements from GT and G2.
*/
func Hash(a []*bn256.GT, D *bn256.G2) (*big.Int, error) {
    digest := sha256.New()
    for i := range a {
        digest.Write([]byte(a[i].String()))
    }
    digest.Write([]byte(D.String()))
    output := digest.Sum(nil)
    tmp := output[0:]
    return byteconversion.FromByteArray(tmp)
}
