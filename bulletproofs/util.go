package bulletproofs

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/mvdbos/zkpsdk/crypto/p256"
	"github.com/mvdbos/zkpsdk/util/bn"
	"github.com/mvdbos/zkpsdk/util/intconversion"
	"math/big"
)

type pstring struct {
	X string
	Y string
}

type ipstring struct {
	N  int64
	A  string
	B  string
	U  pstring
	P  pstring
	Gg pstring
	Hh pstring
	Ls []pstring
	Rs []pstring
	//Params ipgenstring
	Params []byte
}

func (p *BulletProof) MarshalJSON() ([]byte, error) {
	type Alias BulletProof
	var iLs []pstring
	var iRs []pstring
	var i int
	logn := len(p.InnerProductProof.Ls)
	iLs = make([]pstring, logn)
	iRs = make([]pstring, logn)
	i = 0
	for i < logn {
		iLs[i] = pstring{X: p.InnerProductProof.Ls[i].X.String(), Y: p.InnerProductProof.Ls[i].Y.String()}
		iRs[i] = pstring{X: p.InnerProductProof.Rs[i].X.String(), Y: p.InnerProductProof.Rs[i].Y.String()}
		i = i + 1
	}
	pp, _ := p.Params.MarshalJSON()
	ppip, _ := p.InnerProductProof.Params.MarshalJSON()
	return json.Marshal(&struct {
		V       pstring   `json:"V"`
		A       pstring   `json:"A"`
		S       pstring   `json:"S"`
		T1      pstring   `json:"T1"`
		T2      pstring   `json:"T2"`
		Taux    string    `json:"Taux"`
		Mu      string    `json:"Mu"`
		Tprime  string    `json:"Tprime"`
		Commit  pstring   `json:"Commit"`
		Params  []byte    `json:"Params"`
		Proofip ipstring  `json:"InnerProductProof"`
		*Alias
	}{
		V:      pstring{X: p.V.X.String(), Y: p.V.Y.String()},
		A:      pstring{X: p.A.X.String(), Y: p.A.Y.String()},
		S:      pstring{X: p.S.X.String(), Y: p.S.Y.String()},
		T1:     pstring{X: p.T1.X.String(), Y: p.T1.Y.String()},
		T2:     pstring{X: p.T2.X.String(), Y: p.T2.Y.String()},
		Mu:     p.Mu.String(),
		Taux:   p.Taux.String(),
		Tprime: p.Tprime.String(),
		Commit: pstring{X: p.Commit.X.String(), Y: p.Commit.Y.String()},
		Params: pp,
		Proofip: ipstring{
			N:  p.InnerProductProof.N,
			A:  p.InnerProductProof.A.String(),
			B:  p.InnerProductProof.B.String(),
			U:  pstring{X: p.InnerProductProof.U.X.String(), Y: p.InnerProductProof.U.Y.String()},
			P:  pstring{X: p.InnerProductProof.P.X.String(), Y: p.InnerProductProof.P.Y.String()},
			Gg: pstring{X: p.InnerProductProof.Gg.X.String(), Y: p.InnerProductProof.Gg.Y.String()},
			Hh: pstring{X: p.InnerProductProof.Hh.X.String(), Y: p.InnerProductProof.Hh.Y.String()},
			Ls: iLs,
			Rs: iRs,
			Params: ppip, 
		},
		Alias: (*Alias)(p),
	})
}

func (p *BulletProof) UnmarshalJSON(data []byte) error {
	type Alias BulletProof
	aux := &struct {
		V       pstring   `json:"V"`
		A       pstring   `json:"A"`
		S       pstring   `json:"S"`
		T1      pstring   `json:"T1"`
		T2      pstring   `json:"T2"`
		Taux    string    `json:"Taux"`
		Mu      string    `json:"Mu"`
		Tprime  string    `json:"Tprime"`
		Commit  pstring   `json:"Commit"`
		Params  []byte `json:"Params"`
		Proofip ipstring  `json:"InnerProductProof"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	valVX, _ := new(big.Int).SetString(aux.V.X, 10)
	valVY, _ := new(big.Int).SetString(aux.V.Y, 10)
	valAX, _ := new(big.Int).SetString(aux.A.X, 10)
	valAY, _ := new(big.Int).SetString(aux.A.Y, 10)
	valSX, _ := new(big.Int).SetString(aux.S.X, 10)
	valSY, _ := new(big.Int).SetString(aux.S.Y, 10)
	valT1X, _ := new(big.Int).SetString(aux.T1.X, 10)
	valT1Y, _ := new(big.Int).SetString(aux.T1.Y, 10)
	valT2X, _ := new(big.Int).SetString(aux.T2.X, 10)
	valT2Y, _ := new(big.Int).SetString(aux.T2.Y, 10)
	valCommitX, _ := new(big.Int).SetString(aux.Commit.X, 10)
	valCommitY, _ := new(big.Int).SetString(aux.Commit.Y, 10)
	valN := aux.Proofip.N
	valA, _ := new(big.Int).SetString(aux.Proofip.A, 10)
	valB, _ := new(big.Int).SetString(aux.Proofip.B, 10)
	valUx, _ := new(big.Int).SetString(aux.Proofip.U.X, 10)
	valUy, _ := new(big.Int).SetString(aux.Proofip.U.Y, 10)
	valPx, _ := new(big.Int).SetString(aux.Proofip.P.X, 10)
	valPy, _ := new(big.Int).SetString(aux.Proofip.P.Y, 10)
	valGgx, _ := new(big.Int).SetString(aux.Proofip.Gg.X, 10)
	valGgy, _ := new(big.Int).SetString(aux.Proofip.Gg.Y, 10)
	valHhx, _ := new(big.Int).SetString(aux.Proofip.Hh.X, 10)
	valHhy, _ := new(big.Int).SetString(aux.Proofip.Hh.Y, 10)

	p.V = &p256.P256{
		X: valVX,
		Y: valVY,
	}
	p.A = &p256.P256{
		X: valAX,
		Y: valAY,
	}
	p.S = &p256.P256{
		X: valSX,
		Y: valSY,
	}
	p.T1 = &p256.P256{
		X: valT1X,
		Y: valT1Y,
	}
	p.T2 = &p256.P256{
		X: valT2X,
		Y: valT2Y,
	}
	p.Commit = &p256.P256{
		X: valCommitX,
		Y: valCommitY,
	}
	var newParams BulletProofSetupParams
	_ = newParams.UnmarshalJSON(aux.Params)
	p.Params = newParams
	valU := &p256.P256{
		X: valUx,
		Y: valUy,
	}
	valP := &p256.P256{
		X: valPx,
		Y: valPy,
	}
	valGg := &p256.P256{
		X: valGgx,
		Y: valGgy,
	}
	valHh := &p256.P256{
		X: valHhx,
		Y: valHhy,
	}
	p.Taux, _ = new(big.Int).SetString(aux.Taux, 10)
	p.Mu, _ = new(big.Int).SetString(aux.Mu, 10)
	p.Tprime, _ = new(big.Int).SetString(aux.Tprime, 10)
	logn := len(aux.Proofip.Ls)
	valLs := make([]*p256.P256, logn)
	valRs := make([]*p256.P256, logn)
	var (
		i      int
		valLsx *big.Int
		valLsy *big.Int
		valRsx *big.Int
		valRsy *big.Int
	)
	i = 0
	for i < logn {
		valLsx, _ = new(big.Int).SetString(aux.Proofip.Ls[i].X, 10)
		valLsy, _ = new(big.Int).SetString(aux.Proofip.Ls[i].Y, 10)
		valLs[i] = &p256.P256{X: valLsx, Y: valLsy}
		valRsx, _ = new(big.Int).SetString(aux.Proofip.Rs[i].X, 10)
		valRsy, _ = new(big.Int).SetString(aux.Proofip.Rs[i].Y, 10)
		valRs[i] = &p256.P256{X: valRsx, Y: valRsy}
		i = i + 1
	}

	var valnewip InnerProductParams
	_ = valnewip.UnmarshalJSON(aux.Proofip.Params)
	//p.InnerProductProof.Params = valnewip

	p.InnerProductProof = InnerProductProof{
		N:  valN,
		A:  valA,
		B:  valB,
		U:  valU,
		P:  valP,
		Gg: valGg,
		Hh: valHh,
		Ls: valLs,
		Rs: valRs,
		Params: valnewip,
	}
	return nil
}

type ipgenstring struct {
	N  int64
	Cc string
	Uu pstring
	H  pstring
	Gg []pstring
	Hh []pstring
	P  pstring
}

func (zkrp *BulletProofSetupParams) MarshalJSON() ([]byte, error) {
	type Alias BulletProofSetupParams
	
	pn := len(zkrp.Gg)
	piGg := make([]pstring, pn)
	piHh := make([]pstring, pn)
	for i:=int(0); i < pn; i++ {
		piGg[i] = pstring{X: zkrp.Gg[i].X.String(), Y: zkrp.Gg[i].Y.String()}
		piHh[i] = pstring{X: zkrp.Hh[i].X.String(), Y: zkrp.Hh[i].Y.String()}
	}

	n := len(zkrp.InnerProductParams.Gg)
	iGg := make([]pstring, n)
	iHh := make([]pstring, n)
	for i:=int(0); i < n; i++ {
		iGg[i] = pstring{X: zkrp.InnerProductParams.Gg[i].X.String(), Y: zkrp.InnerProductParams.Gg[i].Y.String()}
		iHh[i] = pstring{X: zkrp.InnerProductParams.Hh[i].X.String(), Y: zkrp.InnerProductParams.Hh[i].Y.String()}
	}
	
	return json.Marshal(&struct {
		N int64          `json:"N"`
		G pstring        `json:"G"`
		H pstring        `json:"H"`
		Gg []pstring     `json:"Gg"`
		Hh []pstring     `json:"Hh"`
		Zkip ipgenstring `json:"InnerProductParams"`
		*Alias
	}{
		N: zkrp.N,
		G: pstring{X: zkrp.G.X.String(), Y: zkrp.G.Y.String()},
		H: pstring{X: zkrp.H.X.String(), Y: zkrp.H.Y.String()},
		Gg: piGg,
		Hh: piHh,
		Zkip: ipgenstring{
			N:  zkrp.N,
			Cc: zkrp.InnerProductParams.Cc.String(),
			Uu: pstring{X: zkrp.InnerProductParams.Uu.X.String(), Y: zkrp.InnerProductParams.Uu.Y.String()},
			H:  pstring{X: zkrp.InnerProductParams.H.X.String(), Y: zkrp.InnerProductParams.H.Y.String()},
			Gg: iGg,
			Hh: iHh,
			P:  pstring{X: zkrp.InnerProductParams.P.X.String(), Y: zkrp.InnerProductParams.P.Y.String()},
		},
		Alias: (*Alias)(zkrp),
	})
}

func (zkip *InnerProductParams) MarshalJSON() ([]byte, error) {
	type Alias InnerProductParams
	
	n := len(zkip.Gg)
	iGg := make([]pstring, n)
	iHh := make([]pstring, n)
	for i:=int(0); i < n; i++ {
		iGg[i] = pstring{X: zkip.Gg[i].X.String(), Y: zkip.Gg[i].Y.String()}
		iHh[i] = pstring{X: zkip.Hh[i].X.String(), Y: zkip.Hh[i].Y.String()}
	}
	
	return json.Marshal(&struct {
		Zkip ipgenstring `json:"InnerProductParams"`
		*Alias
	}{
		Zkip: ipgenstring{
			N:  zkip.N,
			Cc: zkip.Cc.String(),
			Uu: pstring{X: zkip.Uu.X.String(), Y: zkip.Uu.Y.String()},
			H:  pstring{X: zkip.H.X.String(), Y: zkip.H.Y.String()},
			Gg: iGg,
			Hh: iHh,
			P:  pstring{X: zkip.P.X.String(), Y: zkip.P.Y.String()},
		},
		Alias: (*Alias)(zkip),
	})
}

func (zkip *InnerProductParams) UnmarshalJSON(data []byte) error {
	type Alias InnerProductParams
	aux := &struct {
		Zkip ipgenstring `json:"InnerProductParams"`
		*Alias
	}{
		Alias: (*Alias)(zkip),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	n := aux.N
	valGg := make([]*p256.P256, n)
	valHh := make([]*p256.P256, n)
	for i:=int64(0); i < n; i++ {
		valGgx, _ := new(big.Int).SetString(aux.Zkip.Gg[i].X, 10)
		valGgy, _ := new(big.Int).SetString(aux.Zkip.Gg[i].Y, 10)
		valGg[i] = &p256.P256{X: valGgx, Y: valGgy}
		valHhx, _ := new(big.Int).SetString(aux.Zkip.Hh[i].X, 10)
		valHhy, _ := new(big.Int).SetString(aux.Zkip.Hh[i].Y, 10)
		valHh[i] = &p256.P256{X: valHhx, Y: valHhy}
	}
	valN := aux.N
	valCc, _ := new(big.Int).SetString(aux.Zkip.Cc, 10)
	valUux, _ := new(big.Int).SetString(aux.Zkip.Uu.X, 10)
	valUuy, _ := new(big.Int).SetString(aux.Zkip.Uu.Y, 10)
	valHx, _ := new(big.Int).SetString(aux.Zkip.H.X, 10)
	valHy, _ := new(big.Int).SetString(aux.Zkip.H.Y, 10)
	valPx, _ := new(big.Int).SetString(aux.Zkip.P.X, 10)
	valPy, _ := new(big.Int).SetString(aux.Zkip.P.Y, 10)
	valUu := &p256.P256{
		X: valUux,
		Y: valUuy,
	}
	valH := &p256.P256{
		X: valHx,
		Y: valHy,
	}
	valP := &p256.P256{
		X: valPx,
		Y: valPy,
	}
	zkip.N = valN
	zkip.Cc = valCc
	zkip.Uu = valUu
	zkip.H = valH
	zkip.Gg = valGg
	zkip.Hh = valHh
	zkip.P = valP
	return nil
}

func (zkrp *BulletProofSetupParams) UnmarshalJSON(data []byte) error {
	type Alias BulletProofSetupParams
	aux := &struct {
		N int64          `json:"N"`
		G pstring        `json:"G"`
		H pstring        `json:"H"`
		Gg []pstring     `json:"Gg"`
		Hh []pstring     `json:"Hh"`
		Zkip ipgenstring `json:"InnerProductParams"`
		*Alias
	}{
		Alias: (*Alias)(zkrp),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	pvalGx, _ := new(big.Int).SetString(aux.G.X, 10)
	pvalGy, _ := new(big.Int).SetString(aux.G.Y, 10)
	pvalHx, _ := new(big.Int).SetString(aux.H.X, 10)
	pvalHy, _ := new(big.Int).SetString(aux.H.Y, 10)
	pn := aux.N
	pvalGg := make([]*p256.P256, pn)
	pvalHh := make([]*p256.P256, pn)
	for i:=int64(0); i < pn; i++ {
		pvalGgx, _ := new(big.Int).SetString(aux.Gg[i].X, 10)
		pvalGgy, _ := new(big.Int).SetString(aux.Gg[i].Y, 10)
		pvalGg[i] = &p256.P256{X: pvalGgx, Y: pvalGgy}
		pvalHhx, _ := new(big.Int).SetString(aux.Hh[i].X, 10)
		pvalHhy, _ := new(big.Int).SetString(aux.Hh[i].Y, 10)
		pvalHh[i] = &p256.P256{X: pvalHhx, Y: pvalHhy}
	}
	n := aux.N
	valGg := make([]*p256.P256, n)
	valHh := make([]*p256.P256, n)
	for i:=int64(0); i < n; i++ {
		valGgx, _ := new(big.Int).SetString(aux.Zkip.Gg[i].X, 10)
		valGgy, _ := new(big.Int).SetString(aux.Zkip.Gg[i].Y, 10)
		valGg[i] = &p256.P256{X: valGgx, Y: valGgy}
		valHhx, _ := new(big.Int).SetString(aux.Zkip.Hh[i].X, 10)
		valHhy, _ := new(big.Int).SetString(aux.Zkip.Hh[i].Y, 10)
		valHh[i] = &p256.P256{X: valHhx, Y: valHhy}
	}
	valN := aux.N
	valCc, _ := new(big.Int).SetString(aux.Zkip.Cc, 10)
	valUux, _ := new(big.Int).SetString(aux.Zkip.Uu.X, 10)
	valUuy, _ := new(big.Int).SetString(aux.Zkip.Uu.Y, 10)
	valHx, _ := new(big.Int).SetString(aux.Zkip.H.X, 10)
	valHy, _ := new(big.Int).SetString(aux.Zkip.H.Y, 10)
	valPx, _ := new(big.Int).SetString(aux.Zkip.P.X, 10)
	valPy, _ := new(big.Int).SetString(aux.Zkip.P.Y, 10)
	valUu := &p256.P256{
		X: valUux,
		Y: valUuy,
	}
	valH := &p256.P256{
		X: valHx,
		Y: valHy,
	}
	valP := &p256.P256{
		X: valPx,
		Y: valPy,
	}
	zkrp.N = pn
	zkrp.G = &p256.P256{X: pvalGx, Y: pvalGy}
	zkrp.H = &p256.P256{X: pvalHx, Y: pvalHy}
	zkrp.Gg = pvalGg
	zkrp.Hh = pvalHh
	zkrp.InnerProductParams = InnerProductParams{
		N:  valN,
		Cc: valCc,
		Uu: valUu,
		H:  valH,
		Gg: valGg,
		Hh: valHh,
		P:  valP,
	}
	return nil
}

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
