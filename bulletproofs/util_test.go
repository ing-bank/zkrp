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
    "math"
    "math/big"
    "testing"

    "github.com/ing-bank/zkrp/crypto/p256"
)

/*
Test method powerOf, which must return a vector containing a growing sequence of
powers of 2.
*/
func TestPowerOf(t *testing.T) {
    result := powerOf(new(big.Int).SetInt64(3), 3)
    ok := result[0].Cmp(new(big.Int).SetInt64(1)) == 0
    ok = ok && (result[1].Cmp(new(big.Int).SetInt64(3)) == 0)
    ok = ok && (result[2].Cmp(new(big.Int).SetInt64(9)) == 0)
    if ok != true {
        t.Errorf("Assert failure: expected true, actual: %t", ok)
    }
}

func TestHashBP(t *testing.T) {
    agx, _ := new(big.Int).SetString("110720467414728166769654679803728202169916280248550137472490865118702779748947", 10)
    agy, _ := new(big.Int).SetString("103949684536896233354287911519259186718323435572971865592336813380571928560949", 10)
    sgx, _ := new(big.Int).SetString("78662919066140655151560869958157053125629409725243565127658074141532489435921", 10)
    sgy, _ := new(big.Int).SetString("114946280626097680211499478702679495377587739951564115086530426937068100343655", 10)
    pointa := &p256.P256{X: agx, Y: agy}
    points := &p256.P256{X: sgx, Y: sgy}
    result1, result2, _ := HashBP(pointa, points)
    res1, _ := new(big.Int).SetString("103823382860325249552741530200099120077084118788867728791742258217664299339569", 10)
    res2, _ := new(big.Int).SetString("8192372577089859289404358830067912230280991346287696886048261417244724213964", 10)
    ok1 := result1.Cmp(res1) != 0
    ok2 := result2.Cmp(res2) != 0
    ok := ok1 && ok2
    if ok {
        t.Errorf("Assert failure: expected true, actual: %t", ok)
    }
}

func TestHashBPGx(t *testing.T) {
    gx, _ := new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    gy, _ := new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    point := &p256.P256{X: gx, Y: gy}
    result1, result2, _ := HashBP(point, point)
    res1, _ := new(big.Int).SetString("11897424191990306464486192136408618361228444529783223689021929580052970909263", 10)
    res2, _ := new(big.Int).SetString("22166487799255634251145870394406518059682307840904574298117500050508046799269", 10)
    ok1 := result1.Cmp(res1) != 0
    ok2 := result2.Cmp(res2) != 0
    ok := ok1 && ok2
    if ok {
        t.Errorf("Assert failure: expected true, actual: %t", ok)
    }
}

/*
Scalar Product returns the inner product between 2 vectors.
*/
func TestScalarProduct(t *testing.T) {
    var (
        a, b []*big.Int
    )
    a = make([]*big.Int, 3)
    b = make([]*big.Int, 3)
    a[0] = new(big.Int).SetInt64(7)
    a[1] = new(big.Int).SetInt64(7)
    a[2] = new(big.Int).SetInt64(7)
    b[0] = new(big.Int).SetInt64(3)
    b[1] = new(big.Int).SetInt64(3)
    b[2] = new(big.Int).SetInt64(3)
    result, _ := ScalarProduct(a, b)
    ok := result.Cmp(new(big.Int).SetInt64(63)) == 0
    if ok != true {
        t.Errorf("Assert failure: expected true, actual: %t", ok)
    }
}

func TestIsPowerOfTwo(t *testing.T) {
    power := int64(math.Pow(2, 16))
    ok := IsPowerOfTwo(power) && !IsPowerOfTwo(power + 1)
    if !ok {
        t.Errorf("Assert failure: expected true, actual: %t", ok)
    }
}
