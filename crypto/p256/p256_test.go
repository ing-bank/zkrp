package p256

import (
	"crypto/rand"
	"github.com/mvdbos/zkpsdk/crypto/secp256k1"
	"math/big"
	"testing"
)

const TestCount = 1000

func TestIsZero(t *testing.T) {
	curve := secp256k1.S256()
	a := curve.N.Bytes()
	Ax, Ay := curve.ScalarBaseMult(a)
	p1 := P256{X: Ax, Y: Ay}
	res := p1.IsZero()
	if res != true {
		t.Errorf("Assert failure: expected true, actual: %t", res)
	}
}

func TestAdd(t *testing.T) {
	curve := secp256k1.S256()
	a1 := new(big.Int).SetInt64(71).Bytes()
	A1x, A1y := curve.ScalarBaseMult(a1)
	p1 := &P256{X: A1x, Y: A1y}
	a2 := new(big.Int).SetInt64(17).Bytes()
	A2x, A2y := curve.ScalarBaseMult(a2)
	p2 := &P256{X: A2x, Y: A2y}
	p3 := p1.Add(p1, p2)
	sa := new(big.Int).SetInt64(-88).Bytes()
	sAx, sAy := curve.ScalarBaseMult(sa)
	sp := &P256{X: sAx, Y: sAy}
	p4 := p3.Add(p3, sp)
	res := p4.IsZero()
	if res != true {
		t.Errorf("Assert failure: expected true, actual: %t", res)
	}
}

func TestScalarMultP256(t *testing.T) {
	curve := secp256k1.S256()
	a1 := new(big.Int).SetInt64(71).Bytes()
	Ax, Ay := curve.ScalarBaseMult(a1)
	p1 := &P256{X: Ax, Y: Ay}
	pr := p1.ScalarMult(p1, curve.N)
	res := pr.IsZero()
	if res != true {
		t.Errorf("Assert failure: expected true, actual: %t", res)
	}
}

func TestScalarBaseMult(t *testing.T) {
	a1 := new(big.Int).SetInt64(71)
	p1 := new(P256).ScalarBaseMult(a1)
	res := p1.IsZero()
	if res != false {
		t.Errorf("Assert failure: expected false, actual: %t", res)
	}
}

func TestMapToGroup(t *testing.T) {
	curve := secp256k1.S256()
	m := "Testing Hash-to-point function:"
	p, _ := MapToGroup(m)
	p.ScalarMult(p, curve.N)
}

func BenchmarkScalarMultP256(b *testing.B) {
	a := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rand.Read(a)
		_ = new(P256).ScalarBaseMult(new(big.Int).SetBytes(a))
	}
}
