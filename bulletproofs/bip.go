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
    "crypto/sha256"
    "errors"
    "math/big"

    "github.com/ing-bank/zkrp/crypto/p256"
    "github.com/ing-bank/zkrp/util/bn"
    "github.com/ing-bank/zkrp/util/byteconversion"
)

var SEEDU = "BulletproofsDoesNotNeedTrustedSetupU"

/*
InnerProductParams contains elliptic curve generators used to compute Pedersen
commitments.
*/
type InnerProductParams struct {
    N  int64
    Cc *big.Int
    Uu *p256.P256
    H  *p256.P256
    Gg []*p256.P256
    Hh []*p256.P256
    P  *p256.P256
}

/*
InnerProductProof contains the elements used to verify the Inner Product Proof.
*/
type InnerProductProof struct {
    N      int64
    Ls     []*p256.P256
    Rs     []*p256.P256
    U      *p256.P256
    P      *p256.P256
    Gg     *p256.P256
    Hh     *p256.P256
    A      *big.Int
    B      *big.Int
    Params InnerProductParams
}

/*
SetupInnerProduct is responsible for computing the inner product basic parameters that are common to both
ProveInnerProduct and Verify algorithms.
*/
func setupInnerProduct(H *p256.P256, g, h []*p256.P256, c *big.Int, N int64) (InnerProductParams, error) {
    var params InnerProductParams

    if N <= 0 {
        return params, errors.New("N must be greater than zero")
    } else {
        params.N = N
    }
    if H == nil {
        params.H, _ = p256.MapToGroup(SEEDH)
    } else {
        params.H = H
    }
    if g == nil {
        params.Gg = make([]*p256.P256, params.N)
        for i := int64(0); i < params.N; i++ {
            params.Gg[i], _ = p256.MapToGroup(SEEDH + "g" + string(i))
        }
    } else {
        params.Gg = g
    }
    if h == nil {
        params.Hh = make([]*p256.P256, params.N)
        for i := int64(0); i < params.N; i++ {
            params.Hh[i], _ = p256.MapToGroup(SEEDH + "h" + string(i))
        }
    } else {
        params.Hh = h
    }
    params.Cc = c
    params.Uu, _ = p256.MapToGroup(SEEDU)
    params.P = new(p256.P256).SetInfinity()

    return params, nil
}

/*
proveInnerProduct calculates the Zero Knowledge Proof for the Inner Product argument.
*/
func proveInnerProduct(a, b []*big.Int, P *p256.P256, params InnerProductParams) (InnerProductProof, error) {
    var (
        proof InnerProductProof
        n, m  int64
        Ls    []*p256.P256
        Rs    []*p256.P256
    )

    n = int64(len(a))
    m = int64(len(b))

    if n != m {
        return proof, errors.New("size of first array argument must be equal to the second")
    }

    // Fiat-Shamir:
    // x = Hash(g,h,P,c)
    x, _ := hashIP(params.Gg, params.Hh, P, params.Cc, params.N)
    // Pprime = P.u^(x.c)
    ux := new(p256.P256).ScalarMult(params.Uu, x)
    uxc := new(p256.P256).ScalarMult(ux, params.Cc)
    PP := new(p256.P256).Multiply(P, uxc)
    // Execute Protocol 2 recursively
    proof = computeBipRecursive(a, b, params.Gg, params.Hh, ux, PP, n, Ls, Rs)
    proof.Params = params
    proof.Params.P = PP
    return proof, nil
}

/*
computeBipRecursive is the main recursive function that will be used to compute the inner product argument.
*/
func computeBipRecursive(a, b []*big.Int, g, h []*p256.P256, u, P *p256.P256, n int64, Ls, Rs []*p256.P256) InnerProductProof {
    var (
        proof                            InnerProductProof
        cL, cR, x, xinv, x2, x2inv       *big.Int
        L, R, Lh, Rh, Pprime             *p256.P256
        gprime, hprime, gprime2, hprime2 []*p256.P256
        aprime, bprime, aprime2, bprime2 []*big.Int
    )

    if n == 1 {
        // recursion end
        proof.A = a[0]
        proof.B = b[0]
        proof.Gg = g[0]
        proof.Hh = h[0]
        proof.P = P
        proof.U = u
        proof.Ls = Ls
        proof.Rs = Rs

    } else {
        // recursion

        // nprime := n / 2
        nprime := n / 2 // (20)

        // Compute cL = < a[:n'], b[n':] >                                    // (21)
        cL, _ = ScalarProduct(a[:nprime], b[nprime:])
        // Compute cR = < a[n':], b[:n'] >                                    // (22)
        cR, _ = ScalarProduct(a[nprime:], b[:nprime])
        // Compute L = g[n':]^(a[:n']).h[:n']^(b[n':]).u^cL                   // (23)
        L, _ = VectorExp(g[nprime:], a[:nprime])
        Lh, _ = VectorExp(h[:nprime], b[nprime:])
        L.Multiply(L, Lh)
        L.Multiply(L, new(p256.P256).ScalarMult(u, cL))

        // Compute R = g[:n']^(a[n':]).h[n':]^(b[:n']).u^cR                   // (24)
        R, _ = VectorExp(g[:nprime], a[nprime:])
        Rh, _ = VectorExp(h[nprime:], b[:nprime])
        R.Multiply(R, Rh)
        R.Multiply(R, new(p256.P256).ScalarMult(u, cR))

        // Fiat-Shamir:                                                       // (26)
        x, _, _ = HashBP(L, R)
        xinv = bn.ModInverse(x, ORDER)

        // Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
        gprime = vectorScalarExp(g[:nprime], xinv)
        gprime2 = vectorScalarExp(g[nprime:], x)
        gprime, _ = VectorECAdd(gprime, gprime2)
        // Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
        hprime = vectorScalarExp(h[:nprime], x)
        hprime2 = vectorScalarExp(h[nprime:], xinv)
        hprime, _ = VectorECAdd(hprime, hprime2)

        // Compute P' = L^(x^2).P.R^(x^-2)                                    // (31)
        x2 = bn.Mod(bn.Multiply(x, x), ORDER)
        x2inv = bn.ModInverse(x2, ORDER)
        Pprime = new(p256.P256).ScalarMult(L, x2)
        Pprime.Multiply(Pprime, P)
        Pprime.Multiply(Pprime, new(p256.P256).ScalarMult(R, x2inv))

        // Compute a' = a[:n'].x      + a[n':].x^(-1)                         // (33)
        aprime, _ = VectorScalarMul(a[:nprime], x)
        aprime2, _ = VectorScalarMul(a[nprime:], xinv)
        aprime, _ = VectorAdd(aprime, aprime2)
        // Compute b' = b[:n'].x^(-1) + b[n':].x                              // (34)
        bprime, _ = VectorScalarMul(b[:nprime], xinv)
        bprime2, _ = VectorScalarMul(b[nprime:], x)
        bprime, _ = VectorAdd(bprime, bprime2)

        Ls = append(Ls, L)
        Rs = append(Rs, R)
        // recursion computeBipRecursive(g',h',u,P'; a', b')                  // (35)
        proof = computeBipRecursive(aprime, bprime, gprime, hprime, u, Pprime, nprime, Ls, Rs)
    }
    proof.N = n
    return proof
}

/*
Verify is responsible for the verification of the Inner Product Proof.
*/
func (proof InnerProductProof) Verify() (bool, error) {

    logn := len(proof.Ls)
    var (
        x, xinv, x2, x2inv                   *big.Int
        ngprime, nhprime, ngprime2, nhprime2 []*p256.P256
    )

    gprime := proof.Params.Gg
    hprime := proof.Params.Hh
    Pprime := proof.Params.P
    nprime := proof.N
    for i := int64(0); i < int64(logn); i++ {
        nprime = nprime / 2                        // (20)
        x, _, _ = HashBP(proof.Ls[i], proof.Rs[i]) // (26)
        xinv = bn.ModInverse(x, ORDER)
        // Compute g' = g[:n']^(x^-1) * g[n':]^(x)                            // (29)
        ngprime = vectorScalarExp(gprime[:nprime], xinv)
        ngprime2 = vectorScalarExp(gprime[nprime:], x)
        gprime, _ = VectorECAdd(ngprime, ngprime2)
        // Compute h' = h[:n']^(x)    * h[n':]^(x^-1)                         // (30)
        nhprime = vectorScalarExp(hprime[:nprime], x)
        nhprime2 = vectorScalarExp(hprime[nprime:], xinv)
        hprime, _ = VectorECAdd(nhprime, nhprime2)
        // Compute P' = L^(x^2).P.R^(x^-2)                                    // (31)
        x2 = bn.Mod(bn.Multiply(x, x), ORDER)
        x2inv = bn.ModInverse(x2, ORDER)
        Pprime.Multiply(Pprime, new(p256.P256).ScalarMult(proof.Ls[i], x2))
        Pprime.Multiply(Pprime, new(p256.P256).ScalarMult(proof.Rs[i], x2inv))
    }

    // c == a*b and checks if P = g^a.h^b.u^c                                     // (16)
    ab := bn.Multiply(proof.A, proof.B)
    ab = bn.Mod(ab, ORDER)
    // Compute right hand side
    rhs := new(p256.P256).ScalarMult(gprime[0], proof.A)
    hb := new(p256.P256).ScalarMult(hprime[0], proof.B)
    rhs.Multiply(rhs, hb)
    rhs.Multiply(rhs, new(p256.P256).ScalarMult(proof.U, ab))
    // Compute inverse of left hand side
    nP := Pprime.Neg(Pprime)
    nP.Multiply(nP, rhs)
    // If both sides are equal then nP must be zero                               // (17)
    c := nP.IsZero()

    return c, nil
}

/*
hashIP is responsible for the computing a Zp element given elements from GT and G1.
*/
func hashIP(g, h []*p256.P256, P *p256.P256, c *big.Int, n int64) (*big.Int, error) {
    digest := sha256.New()
    digest.Write([]byte(P.String()))

    for i := int64(0); i < n; i++ {
        digest.Write([]byte(g[i].String()))
        digest.Write([]byte(h[i].String()))
    }

    digest.Write([]byte(c.String()))
    output := digest.Sum(nil)
    tmp := output[0:]
    result, err := byteconversion.FromByteArray(tmp)

    return result, err
}

/*
commitInnerProduct is responsible for calculating g^a.h^b.
*/
func commitInnerProduct(g, h []*p256.P256, a, b []*big.Int) *p256.P256 {
    var (
        result *p256.P256
    )

    ga, _ := VectorExp(g, a)
    hb, _ := VectorExp(h, b)
    result = new(p256.P256).Multiply(ga, hb)
    return result
}

/*
VectorScalarExp computes a[i]^b for each i.
*/
func vectorScalarExp(a []*p256.P256, b *big.Int) []*p256.P256 {
    var (
        result []*p256.P256
        n      int64
    )
    n = int64(len(a))
    result = make([]*p256.P256, n)
    for i := int64(0); i < n; i++ {
        result[i] = new(p256.P256).ScalarMult(a[i], b)
    }
    return result
}
