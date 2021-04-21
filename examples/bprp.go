package main

import (
	"encoding/json"
	"fmt"
	"github.com/ing-bank/zkrp/bulletproofs"
	"math/big"
)

func main() {
	// Set up the range, [18, 200) in this case.
	// We want to prove that we are over 18, and less than 200 years old.
	// This information is shared between the prover and the verifier.
	params, _ := bulletproofs.SetupGeneric(18, 200)

	// Our secret age is 40
	bigSecret := new(big.Int).SetInt64(int64(40))

	// Create the zero-knowledge range proof
	proof, _ := bulletproofs.ProveGeneric(bigSecret, params)

	// Encode the proof to JSON
	jsonEncoded, _ := json.Marshal(proof)

	// It this stage, the proof is passed to the verifier, possibly over a network.

	// Decode the proof from JSON
	var decodedProof bulletproofs.ProofBPRP
	_ = json.Unmarshal(jsonEncoded, &decodedProof)

	// Verify the proof
	ok, _ := decodedProof.Verify()

	if ok == true {
		fmt.Printf("Verified\n")
	} else {
		fmt.Printf("Failed to verify\n")
	}
}
