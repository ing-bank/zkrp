package bulletproofs

import (
	"math"
	"math/big"
	"testing"
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
