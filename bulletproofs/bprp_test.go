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
    "encoding/json"
    "math/big"
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestXWithinGenericRange(t *testing.T) {
    if setupProveVerify18To200(t, 40) != true {
        t.Errorf("secret within range should verify successfully")
    }
}

func TestXEqualToRangeStartGeneric(t *testing.T) {
    if setupProveVerify18To200(t, 18) != true {
        t.Errorf("secret equal to range start should verify successfully")
    }
}

func TestXLessThanRangeStartGeneric(t *testing.T) {
    if setupProveVerify18To200(t, 17) != false {
        t.Errorf("secret less that range start should fail verification")
    }
}

func TestXGreaterThanRangeEndGeneric(t *testing.T) {
    if setupProveVerify18To200(t, 201) != false {
        t.Errorf("secret greater than range end should fail verification")
    }
}

func TestXEqualToRangeEndGeneric(t *testing.T) {
    if setupProveVerify18To200(t, 200) != false {
        t.Errorf("secret equal to range end should fail verification")
    }
}

func setupProveVerify18To200(t *testing.T, secret int) bool {
    params, errSetup := SetupGeneric(18, 200)
    if errSetup != nil {
        t.Errorf(errSetup.Error())
        t.FailNow()
    }
    bigSecret := new(big.Int).SetInt64(int64(secret))
    proof, errProve := ProveGeneric(bigSecret, params)
    if errProve != nil {
        t.Errorf(errProve.Error())
        t.FailNow()
    }
    ok, errVerify := proof.Verify()
    if errVerify != nil {
        t.Errorf(errVerify.Error())
        t.FailNow()
    }
    return ok
}

func TestJsonEncodeDecodeBPRP(t *testing.T) {
    // Set up the range, [18, 200) in this case.
    // We want to prove that we are over 18, and less than 200 years old.
    params, errSetup := SetupGeneric(18, 200)
    if errSetup != nil {
        t.Errorf(errSetup.Error())
        t.FailNow()
    }

    // Create the proof
    bigSecret := new(big.Int).SetInt64(int64(40))
    proof, errProve := ProveGeneric(bigSecret, params)
    if errProve != nil {
        t.Errorf(errProve.Error())
        t.FailNow()
    }

    // Encode the proof to JSON
    jsonEncoded, err := json.Marshal(proof)
    if err != nil {
        t.Fatal("encode error:", err)
    }

    // Here the proof is passed to th verifier, possibly over a network.

    // Decode the proof from JSON
    var decodedProof ProofBPRP
    err = json.Unmarshal(jsonEncoded, &decodedProof)
    if err != nil {
        t.Fatal("decode error:", err)
    }

    assert.Equal(t, proof, decodedProof, "should be equal")

    // Verify the proof
    ok, errVerify := proof.Verify()
    if errVerify != nil {
        t.Errorf(errVerify.Error())
        t.FailNow()
    }
    assert.True(t, ok, "should verify")
}
