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

package p256

import (
    "math/big"

    "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type MyBitCurve struct {
    secp256k1.BitCurve
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (BitCurve *MyBitCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
    z := new(big.Int).SetInt64(1)
    return BitCurve.affineFromJacobian(BitCurve.addJacobian(x1, y1, z, x2, y2, z))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (BitCurve *MyBitCurve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
    // See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
    z1z1 := new(big.Int).Mul(z1, z1)
    z1z1.Mod(z1z1, BitCurve.P)
    z2z2 := new(big.Int).Mul(z2, z2)
    z2z2.Mod(z2z2, BitCurve.P)

    u1 := new(big.Int).Mul(x1, z2z2)
    u1.Mod(u1, BitCurve.P)
    u2 := new(big.Int).Mul(x2, z1z1)
    u2.Mod(u2, BitCurve.P)
    h := new(big.Int).Sub(u2, u1)
    if h.Sign() == -1 {
        h.Add(h, BitCurve.P)
    }
    i := new(big.Int).Lsh(h, 1)
    i.Mul(i, i)
    j := new(big.Int).Mul(h, i)

    s1 := new(big.Int).Mul(y1, z2)
    s1.Mul(s1, z2z2)
    s1.Mod(s1, BitCurve.P)
    s2 := new(big.Int).Mul(y2, z1)
    s2.Mul(s2, z1z1)
    s2.Mod(s2, BitCurve.P)
    r := new(big.Int).Sub(s2, s1)
    if r.Sign() == -1 {
        r.Add(r, BitCurve.P)
    }
    r.Lsh(r, 1)
    v := new(big.Int).Mul(u1, i)

    x3 := new(big.Int).Set(r)
    x3.Mul(x3, x3)
    x3.Sub(x3, j)
    x3.Sub(x3, v)
    x3.Sub(x3, v)
    x3.Mod(x3, BitCurve.P)

    y3 := new(big.Int).Set(r)
    v.Sub(v, x3)
    y3.Mul(y3, v)
    s1.Mul(s1, j)
    s1.Lsh(s1, 1)
    y3.Sub(y3, s1)
    y3.Mod(y3, BitCurve.P)

    z3 := new(big.Int).Add(z1, z2)
    z3.Mul(z3, z3)
    z3.Sub(z3, z1z1)
    if z3.Sign() == -1 {
        z3.Add(z3, BitCurve.P)
    }
    z3.Sub(z3, z2z2)
    if z3.Sign() == -1 {
        z3.Add(z3, BitCurve.P)
    }
    z3.Mul(z3, h)
    z3.Mod(z3, BitCurve.P)

    return x3, y3, z3
}

func (BitCurve *MyBitCurve) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
    if z.Sign() == 0 {
        return new(big.Int), new(big.Int)
    }
    zinv := new(big.Int).ModInverse(z, BitCurve.P)
    zinvsq := new(big.Int).Mul(zinv, zinv)

    xOut = new(big.Int).Mul(x, zinvsq)
    xOut.Mod(xOut, BitCurve.P)
    zinvsq.Mul(zinvsq, zinv)
    yOut = new(big.Int).Mul(y, zinvsq)
    yOut.Mod(yOut, BitCurve.P)
    return
}

var theCurve = new(MyBitCurve)

func init() {
    // See SEC 2 section 2.7.1
    // curve parameters taken from:
    // http://www.secg.org/sec2-v2.pdf
    theCurve.P, _ = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 0)
    theCurve.N, _ = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
    theCurve.B, _ = new(big.Int).SetString("0x0000000000000000000000000000000000000000000000000000000000000007", 0)
    theCurve.Gx, _ = new(big.Int).SetString("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)
    theCurve.Gy, _ = new(big.Int).SetString("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)
    theCurve.BitSize = 256
}

// S256 returns a BitCurve which implements secp256k1.
func S256() *MyBitCurve {
    return theCurve
}
