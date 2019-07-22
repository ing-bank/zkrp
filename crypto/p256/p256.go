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

/*
Package p256 Encapsulates secP256k1 elliptic curve.
*/
package p256

import (
    "bytes"
    "crypto/sha256"
    "errors"
    "math/big"
    "strconv"

    "github.com/ing-bank/zkrp/util/bn"
    "github.com/ing-bank/zkrp/util/byteconversion"
)

var (
    CURVE = S256()
)

/*
Elliptic Curve Point struct.
*/
type P256 struct {
    X, Y *big.Int
}

/*
IsZero returns true if and only if the elliptic curve point is the point at infinity.
*/
func (p *P256) IsZero() bool {
    c1 := p.X == nil || p.Y == nil
    if !c1 {
        z := new(big.Int).SetInt64(0)
        return p.X.Cmp(z) == 0 && p.Y.Cmp(z) == 0
    }
    return true
}

/*
Neg returns the inverse of the given elliptic curve point.
*/
func (p *P256) Neg(a *P256) *P256 {
    // (X, Y) -> (X, X + Y)
    if a.IsZero() {
        return p.SetInfinity()
    }
    one := new(big.Int).SetInt64(1)
    mone := new(big.Int).Sub(CURVE.N, one)
    p.ScalarMult(p, mone)
    return p
}

/*
Input points must be distinct
*/
func (p *P256) Add(a, b *P256) *P256 {
    if a.IsZero() {
        p.X = b.X
        p.Y = b.Y
        return p
    } else if b.IsZero() {
        p.X = b.X
        p.Y = b.Y
        return p

    }
    resx, resy := CURVE.Add(a.X, a.Y, b.X, b.Y)
    p.X = resx
    p.Y = resy
    return p
}

/*
Double returns 2*P, where P is the given elliptic curve point.
*/
func (p *P256) Double(a *P256) *P256 {
    if a.IsZero() {
        return p.SetInfinity()
    }
    resx, resy := CURVE.Double(a.X, a.Y)
    p.X = resx
    p.Y = resy
    return p
}

/*
ScalarMul encapsulates the scalar Multiplication Algorithm from secP256k1.
*/
func (p *P256) ScalarMult(a *P256, n *big.Int) *P256 {
    if a.IsZero() {
        return p.SetInfinity()
    }
    cmp := n.Cmp(big.NewInt(0))
    if cmp == 0 {
        return p.SetInfinity()
    }
    n = bn.Mod(n, CURVE.N)
    bns := n.Bytes()
    resx, resy := CURVE.ScalarMult(a.X, a.Y, bns)
    p.X = resx
    p.Y = resy
    return p
}

/*
ScalarBaseMult returns the Scalar Multiplication by the base generator.
*/
func (p *P256) ScalarBaseMult(n *big.Int) *P256 {
    cmp := n.Cmp(big.NewInt(0))
    if cmp == 0 {
        return p.SetInfinity()
    }
    n = bn.Mod(n, CURVE.N)
    bns := n.Bytes()
    resx, resy := CURVE.ScalarBaseMult(bns)
    p.X = resx
    p.Y = resy
    return p
}

/*
Multiply actually is reponsible for the addition of elliptic curve points.
The name here is to maintain compatibility with bn256 interface.
This algorithm verifies if the given elliptic curve points are equal, in which case it
returns the result of Double function, otherwise it returns the result of Add function.
*/
func (p *P256) Multiply(a, b *P256) *P256 {
    if a.IsZero() {
        p.X = b.X
        p.Y = b.Y
        return p
    } else if b.IsZero() {
        p.X = a.X
        p.Y = a.Y
        return p
    }
    if a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0 {
        resx, resy := CURVE.Double(a.X, a.Y)
        p.X = resx
        p.Y = resy
        return p
    }
    resx, resy := CURVE.Add(a.X, a.Y, b.X, b.Y)
    p.X = resx
    p.Y = resy
    return p
}

/*
SetInfinity sets the given elliptic curve point to the point at infinity.
*/
func (p *P256) SetInfinity() *P256 {
    p.X = nil
    p.Y = nil
    return p
}

/*
String returns the readable representation of the given elliptic curve point, i.e.
the tuple formed by X and Y coordinates.
*/
func (p *P256) String() string {
    return "P256(" + p.X.String() + "," + p.Y.String() + ")"
}

/*
MapToGroup is a hash function that returns a valid elliptic curve point given as
input a string. It is also known as hash-to-point and is used to obtain a generator
that has no discrete logarithm known relation, thus addressing the concept of
NUMS (nothing up my sleeve).
This implementation is based on the paper:
Short signatures from the Weil pairing
Boneh, Lynn and Shacham
Journal of Cryptology, September 2004, Volume 17, Issue 4, pp 297–319
*/
func MapToGroup(m string) (*P256, error) {
    var (
        i      int
        buffer bytes.Buffer
    )
    i = 0
    for i < 256 {
        buffer.Reset()
        buffer.WriteString(strconv.Itoa(i))
        buffer.WriteString(m)
        x, _ := HashToInt(buffer)
        x = bn.Mod(x, CURVE.P)
        fx, _ := F(x)
        fx = bn.Mod(fx, CURVE.P)
        y := fx.ModSqrt(fx, CURVE.P)
        if y != nil {
            p := &P256{X: x, Y: y}
            if p.IsOnCurve() && !p.IsZero() {
                return p, nil
            }
        }
        i = i + 1
    }
    return nil, errors.New("Failed to Hash-to-point.")
}

/*
F receives a big integer x as input and return x^3 + 7 mod ORDER.
*/
func F(x *big.Int) (*big.Int, error) {
    // Compute x^2
    x3p7 := bn.Multiply(x, x)
    x3p7 = bn.Mod(x3p7, CURVE.P)
    // Compute x^3
    x3p7 = bn.Multiply(x3p7, x)
    x3p7 = bn.Mod(x3p7, CURVE.P)
    // Compute X^3 + 7
    x3p7 = bn.Add(x3p7, new(big.Int).SetInt64(7))
    x3p7 = bn.Mod(x3p7, CURVE.P)
    return x3p7, nil
}

/*
Hash is responsible for the computing a Zp element given the input string.
*/
func HashToInt(b bytes.Buffer) (*big.Int, error) {
    digest := sha256.New()
    digest.Write(b.Bytes())
    output := digest.Sum(nil)
    tmp := output[0:]
    return byteconversion.FromByteArray(tmp)
}

/*
IsOnCurve returns TRUE if and only if p has coordinates X and Y that satisfy the
Elliptic Curve equation: y^2 = x^3 + 7.
*/
func (p *P256) IsOnCurve() bool {
    // y² = x³ + 7
    y2 := new(big.Int).Mul(p.Y, p.Y)
    y2.Mod(y2, CURVE.P)

    x3 := new(big.Int).Mul(p.X, p.X)
    x3.Mul(x3, p.X)

    x3.Add(x3, new(big.Int).SetInt64(7))
    x3.Mod(x3, CURVE.P)

    return x3.Cmp(y2) == 0
}
