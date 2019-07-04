package bulletproofs

import (
    "encoding/json"
    "math"
    "math/big"
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestXEqualsRangeStart(t *testing.T) {
    rangeEnd := int64(math.Pow(2, 32))
    x := new(big.Int).SetInt64(0)

    params := setupRange(t, rangeEnd)
    if proveAndVerifyRange(x, params) != true {
        t.Errorf("x equal to range start should verify successfully")
    }
}

func TestXLowerThanRangeStart(t *testing.T) {
    rangeEnd := int64(math.Pow(2, 32))
    x := new(big.Int).SetInt64(-1)

    params := setupRange(t, rangeEnd)
    if proveAndVerifyRange(x, params) == true {
        t.Errorf("x lower than range start should not verify")
    }
}

func TestXHigherThanRangeEnd(t *testing.T) {
    rangeEnd := int64(math.Pow(2, 32))
    x := new(big.Int).SetInt64(rangeEnd + 1)

    params := setupRange(t, rangeEnd)
    if proveAndVerifyRange(x, params) == true {
        t.Errorf("x higher than range end should not verify")
    }
}

func TestXEqualToRangeEnd(t *testing.T) {
    rangeEnd := int64(math.Pow(2, 32))
    x := new(big.Int).SetInt64(rangeEnd)

    params := setupRange(t, rangeEnd)
    if proveAndVerifyRange(x, params) == true {
        t.Errorf("x equal to range end should not verify")
    }
}

func TestXWithinRange(t *testing.T) {
    rangeEnd := int64(math.Pow(2, 32))
    x := new(big.Int).SetInt64(3)

    params := setupRange(t, rangeEnd)
    if proveAndVerifyRange(x, params) != true {
        t.Errorf("x within range should verify successfully")
    }
}

func setupRange(t *testing.T, rangeEnd int64) BulletProofSetupParams {
    params, err := Setup(rangeEnd)
    if err != nil {
        t.Errorf("Invalid range end: %s", err)
        t.FailNow()
    }
    return params
}

func proveAndVerifyRange(x *big.Int, params BulletProofSetupParams) bool {
    proof, _ := Prove(x, params)
    ok, _ := proof.Verify()
    return ok
}

func TestJsonEncodeDecode(t *testing.T) {
    params, _ := Setup(MAX_RANGE_END)
    proof, _ := Prove(new(big.Int).SetInt64(18), params)
    jsonEncoded, err := json.Marshal(proof)
    if err != nil {
        t.Fatal("encode error:", err)
    }

    // network transfer takes place here

    var decodedProof BulletProof
    err = json.Unmarshal(jsonEncoded, &decodedProof)
    if err != nil {
        t.Fatal("decode error:", err)
    }

    assert.Equal(t, proof, decodedProof, "should be equal")

    ok, err := decodedProof.Verify()
    if err != nil {
        t.Fatal("verify error:", err)
    }
    assert.True(t, ok, "should verify")
}
