[![GoDoc](https://godoc.org/github.com/ing-bank/zkrp?status.svg)](https://godoc.org/github.com/ing-bank/zkrp)

# Zero Knowledge Proofs
 
 This repository contains ING's implementations of **Bulletproofs**, **Zero Knowledge Range Proof (ZKRP)** and **Zero Knowledge Set Membership (ZKSM)**. The current implementations are based on the following papers:
 * Range Proofs based on the paper: [Efficient Proofs that a Committed Number Lies in an Interval](https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf) by **Fabrice Boudot**.
 * Set Membership Proofs based on the paper: [Efficient protocols for set membership and range proofs](https://infoscience.epfl.ch/record/128718/files/CCS08.pdf), by **Jan Camenisch, Rafik Chaabouni and Abhi Shelat**.
 * Bulletproofs based on paper: [Bulletproofs: Short Proofs for Confidential Transactions and More](https://eprint.iacr.org/2017/1066.pdf), by **Benedikt Bünz, Jonathan Bootle, Dan Boneh, Andrew Poelstra, Pieter Wuille and Greg Maxwell**.
 
## Zero Knowledge Range Proofs

One fundamental concern in blockchain technology is the confidentiality of the data. In order to reach consensus between all independent nodes, each node must be able to validate all transactions (for instance against double-spend), in most cases this means that the content of the transactions is visible to all nodes. Fortunately, several solutions exist that preserve confidentiality on a blockchain (private transactions, HyperLedger Fabric Channels, Payment Channels, Homomorphic encryption, transaction-mixing, zero knowledge proofs etc.).

The Zero Knowledge Range Proof allows the blockchain network to validate that a secret number is within known limits without disclosing the secret number. This is useful to reach consensus in a variety of use cases:

 * Validate that someone's age is between 18 and 65 without disclosing the age.
 * Validate that someone is in Europe without disclosing the exact location.
 * Validate that a payment-amount is positive without disclosing the amount (as done by Monero).

The Zero Knowledge Range Proof requires a commitment on a number by a trusted party (for instance a government committing on someone's age). This commitment can be used to by someone who wants to prove their age can to generate a range proof. The verifier can then verify this proof. If it verifies, it means the committed, secret age of the prover lies within the agreed range.

## Zero Knowledge Set Membership Proofs

> **Since ZKRP is a subcase of ZK Set Membership Proofs, the latter may be used as a replacement of ZKRP. This is interesting because for certain scenarios it performs better.**

ZKSM allows to prove that some secret value is an element of a determined set, without disclosing which value. We can do the following examples using it:

* Prove that we live in a country that belongs to the European Union. 
* Validation of KYC private data. For example, proving that a postcode is valid, without revealing it. 
* Private Identity Management Systems.
* Other interesting applications like: Anti-Money Laundering (AML) and Common Reference Standard (CRS).

## Bulletproofs

In 2017 researchers proposed the scheme called Bulletproofs to provide a more efficient solution for Zero Knowledge Range Proofs (ZKRP). It was specifically designed for Blockchain, where it is important to have short proofs. For instance, Bulletproofs allows to construct proofs whose size is only logarithmic with respect to the input size. Also, Bulletproofs doesn't require a trusted setup, solving an important problem in order to use this technology to solve practical problems. Previous solutions do require a trusted setup, what means that if the setup is not carried out in an appropriate way, then it would be possible to generate fake ZK proofs. 

Bulletproofs can be used to solve the abovementioned problems and even more, because it is possible to use it for any computable function which requires privacy for its input data. Therefore, Bulletproofs is similiar to zk-SNARKs and zk-STARKs. However, this functionalities were not yet implemented and should be considered as future work. In particular, Bulletproofs seems an interesting building block to construct private smart contracts. 

### Bulletproofs example

Next we show how to use Bulletproofs to construct a Zero Knowledge Range Proof. 
The first step is to setup the scheme, passing as parameter the lower and upper bounds. 
The second step is to call the method that generates the proof. 
Finally the verifier can check if the proof is valid or not. 
It is important to remark that the data stored in the proof does not reveal information about the secret information, 
which in this example is the number 40.

This example code does not handle errors for simplicity, please check [bulletproofs/bprp_test.go:61](bulletproofs/bprp_test.go) 
for a working implementation with error handling.

```go
// Set up the range, [18, 200) in this case.
// We want to prove that we are over 18, and less than 200 years old.
// This information is shared between the prover and the verifier.
params, _ := SetupGeneric(18, 200)

// Our secret age is 40
bigSecret := new(big.Int).SetInt64(int64(40))

// Create the zero-knowledge range proof
proof, _ := ProveGeneric(bigSecret, params)

// Encode the proof to JSON
jsonEncoded, _ := json.Marshal(proof)

// It this stage, the proof is passed to th verifier, possibly over a network.

// Decode the proof from JSON
var decodedProof ProofBPRP
_ = json.Unmarshal(jsonEncoded, &decodedProof)

// Verify the proof
ok, _ := proof.Verify()

if ok == true {
    println("Age verified to be [18, 200)")
}
```

## Contribute :wave:

We would love your contributions. Please feel free to submit any PR.

### Code quality & Git hook

To ensure the quality of our project, we run certain checks in our CI pipeline. 
To make sure that your PR is accepted, and to prevent a longer feedback loop (waiting for CI results), please make sure your PR
adheres our standards by running the following checks locally before submitting your PR:

* golangci-lint
* errcheck
* all unit tests

A convenient way to do that is by running `.bin/check.sh` from the root of the repo.
Alternatively, you can enable a git pre-push hook that runs these checks locally.

To do that, create a file called `.git/hooks/pre-push` in the project directory, make it executable and put the following in it:

```$bash
#!/usr/bin/env bash

cd $(git rev-parse --show-toplevel)
.bin/check.sh
```

Prerequisites: 

* have golangci-lint installed: `go get -u github.com/golangci/golangci-lint/cmd/golangci-lint` 
* have errcheck installed: `go get -u github.com/kisielk/errcheck`

If you want, you can create a hook for pre-commit as well that does the same: just symlink `.git/hooks/pre-commit` to `.git/hooks/pre-push`.
Then these checks will be executed on every local commit.

## License

This repository is GNU Lesser General Public License v3.0 licensed, as found in [LICENSE file](LICENSE) and [LICENSE.LESSER file](LICENSE.LESSER).