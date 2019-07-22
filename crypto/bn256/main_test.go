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

package bn256

import (
    "testing"

    "github.com/ing-bank/zkrp/util/intconversion"
)

func TestPairings(t *testing.T) {
    a1 := new(G1).ScalarBaseMult(intconversion.BigFromBase10("1"))
    a2 := new(G1).ScalarBaseMult(intconversion.BigFromBase10("2"))
    a37 := new(G1).ScalarBaseMult(intconversion.BigFromBase10("37"))
    an1 := new(G1).ScalarBaseMult(intconversion.BigFromBase10("21888242871839275222246405745257275088548364400416034343698204186575808495616"))

    b0 := new(G2).ScalarBaseMult(intconversion.BigFromBase10("0"))
    b1 := new(G2).ScalarBaseMult(intconversion.BigFromBase10("1"))
    b2 := new(G2).ScalarBaseMult(intconversion.BigFromBase10("2"))
    b27 := new(G2).ScalarBaseMult(intconversion.BigFromBase10("27"))
    b999 := new(G2).ScalarBaseMult(intconversion.BigFromBase10("999"))
    bn1 := new(G2).ScalarBaseMult(intconversion.BigFromBase10("21888242871839275222246405745257275088548364400416034343698204186575808495616"))

    p1 := Pair(a1, b1)
    pn1 := Pair(a1, bn1)
    np1 := Pair(an1, b1)
    if pn1.String() != np1.String() {
        t.Error("Pairing mismatch: e(a, -b) != e(-a, b)")
    }
    if !PairingCheck([]*G1{a1, an1}, []*G2{b1, b1}) {
        t.Error("MultiAte check gave false negative!")
    }
    p0 := new(GT).Add(p1, pn1)
    p0_2 := Pair(a1, b0)
    if p0.String() != p0_2.String() {
        t.Error("Pairing mismatch: e(a, b) * e(a, -b) != 1")
    }
    p0_3 := new(GT).ScalarMult(p1, intconversion.BigFromBase10("21888242871839275222246405745257275088548364400416034343698204186575808495617"))
    if p0.String() != p0_3.String() {
        t.Error("Pairing mismatch: e(a, b) has wrong order")
    }
    p2 := Pair(a2, b1)
    p2_2 := Pair(a1, b2)
    p2_3 := new(GT).ScalarMult(p1, intconversion.BigFromBase10("2"))
    if p2.String() != p2_2.String() {
        t.Error("Pairing mismatch: e(a, b * 2) != e(a * 2, b)")
    }
    if p2.String() != p2_3.String() {
        t.Error("Pairing mismatch: e(a, b * 2) != e(a, b) ** 2")
    }
    if p2.String() == p1.String() {
        t.Error("Pairing is degenerate!")
    }
    if PairingCheck([]*G1{a1, a1}, []*G2{b1, b1}) {
        t.Error("MultiAte check gave false positive!")
    }
    p999 := Pair(a37, b27)
    p999_2 := Pair(a1, b999)
    if p999.String() != p999_2.String() {
        t.Error("Pairing mismatch: e(a * 37, b * 27) != e(a, b * 999)")
    }
}
