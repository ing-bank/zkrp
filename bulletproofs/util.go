package bulletproofs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/mvdbos/zkpsdk/crypto/p256"
	"github.com/mvdbos/zkpsdk/util/bn"
	"github.com/mvdbos/zkpsdk/util/intconversion"
)

/*
powerOf returns a vector composed by powers of x.
*/
func powerOf(x *big.Int, n int64) []*big.Int {
	var (
		i      int64
		result []*big.Int
	)
	result = make([]*big.Int, n)
	current := intconversion.BigFromBase10("1")
	i = 0
	for i < n {
		result[i] = current
		current = bn.Multiply(current, x)
		current = bn.Mod(current, ORDER)
		i = i + 1
	}
	return result
}

/*
Hash is responsible for the computing a Zp element given elements from GT and G1.
*/
func HashBP(A, S *p256.P256) (*big.Int, *big.Int, error) {

	digest1 := sha256.New()
	var buffer bytes.Buffer
	buffer.WriteString(A.X.String())
	buffer.WriteString(A.Y.String())
	buffer.WriteString(S.X.String())
	buffer.WriteString(S.Y.String())
	digest1.Write(buffer.Bytes())
	output1 := digest1.Sum(nil)
	tmp1 := output1[0:]
	result1 := new(big.Int).SetBytes(tmp1)

	digest2 := sha256.New()
	var buffer2 bytes.Buffer
	buffer2.WriteString(A.X.String())
	buffer2.WriteString(A.Y.String())
	buffer2.WriteString(S.X.String())
	buffer2.WriteString(S.Y.String())
	buffer2.WriteString(result1.String())
	digest2.Write(buffer.Bytes())
	output2 := digest2.Sum(nil)
	tmp2 := output2[0:]
	result2 := new(big.Int).SetBytes(tmp2)

	return result1, result2, nil
}

/*
VectorExp computes Prod_i^n{a[i]^b[i]}.
*/
func VectorExp(a []*p256.P256, b []*big.Int) (*p256.P256, error) {
	var (
		result  *p256.P256
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = new(p256.P256).SetInfinity()
	for i < n {
		result.Multiply(result, new(p256.P256).ScalarMult(a[i], b[i]))
		i = i + 1
	}
	return result, nil
}

/*
ScalarProduct return the inner product between a and b.
*/
func ScalarProduct(a, b []*big.Int) (*big.Int, error) {
	var (
		result  *big.Int
		i, n, m int64
	)
	n = int64(len(a))
	m = int64(len(b))
	if n != m {
		return nil, errors.New("Size of first argument is different from size of second argument.")
	}
	i = 0
	result = intconversion.BigFromBase10("0")
	for i < n {
		ab := bn.Multiply(a[i], b[i])
		result.Add(result, ab)
		result = bn.Mod(result, ORDER)
		i = i + 1
	}
	return result, nil
}

/*
IsPowerOfTwo returns true for arguments that are a power of 2, false otherwise.
https://stackoverflow.com/a/600306/844313
*/
func IsPowerOfTwo(x int64) bool {
	return (x != 0) && ((x & (x - 1)) == 0)
}
