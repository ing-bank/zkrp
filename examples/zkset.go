package main

import (
	"crypto/rand"
	"fmt"
	"github.com/ing-bank/zkrp/ccs08"
	"github.com/ing-bank/zkrp/crypto/bn256"
)

// Tests the ZK Set Membership (CCS08) protocol.
func main() {
	s := []int64{12, 42, 61, 71}

	p, pErr := ccs08.SetupSet(s)
	if pErr != nil {
		panic(pErr)
	}

	r, rErr := rand.Int(rand.Reader, bn256.Order)
	if rErr != nil {
		panic(rErr)
	}

	proof, err := ccs08.ProveSet(12, r, p)
	if err != nil {
		panic(err)
	}

	result, _ := ccs08.VerifySet(&proof, &p)
	if result != true {
		fmt.Printf("Verify failed\n")
	} else {
		fmt.Printf("Verified\n")
	}
}
