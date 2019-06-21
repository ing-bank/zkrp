package bulletproofs

import (
	"math/big"
	"testing"
)

func TestXWithinGenericRange(t *testing.T) {
	if setupProveVerify18To200(t, 40) != true {
		t.Errorf("x within range should verify successfully")
	}
}

func TestXEqualToRangeStartGeneric(t *testing.T) {
	if setupProveVerify18To200(t, 18) != true {
		t.Errorf("x equal to range start should verify successfully")
	}
}

func TestXLessThanRangeStartGeneric(t *testing.T) {
	if setupProveVerify18To200(t, 17) != false {
		t.Errorf("x less that range start should fail verification")
	}
}

func TestXGreaterThanRangeEndGeneric(t *testing.T) {
	if setupProveVerify18To200(t, 201) != false {
		t.Errorf("x greater than range end should fail verification")
	}
}

func TestXEqualToRangeEndGeneric(t *testing.T) {
	if setupProveVerify18To200(t, 200) != false {
		t.Errorf("x equal to range end should fail verification")
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
