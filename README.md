# ING ZKP SDK FTW

## Zero Knowledge Proofs
 
 This repository contains ING's **Zero Knowledge Range Proof (ZKRP)** and **Zero Knowledge Set Membership (ZKSM)**. The current implementations are based on the following papers:
 * Range Proofs based on the paper: [Efficient Proofs that a Committed Number Lies in an Interval](https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf) by **Fabrice Boudot**.
 * Set Membership Proofs based on the paper: [Efficient protocols for set membership and range proofs](https://infoscience.epfl.ch/record/128718/files/CCS08.pdf), by **Jan Camenisch, Rafik Chaabouni and Abhi Shelat**.
 * Bulletproofs based on paper: [Bulletproofs: Short Proofs for Confidential Transactions and More](https://eprint.iacr.org/2017/1066.pdf), by **Benedikt Bünz, Jonathan Bootle, Dan Boneh, Andrew Poelstra, Pieter Wuille and Greg Maxwell**.
 
### Bulletproofs

```
package main
 
import (
        "github.com/mvdbos/zkpsdk/bulletproofs"
        "math/big"
        "fmt"
)

func main() {
         params, errSetup := bulletproofs.SetupGeneric(18, 200)
         if errSetup == nil { 
                 bigSecret := new(big.Int).SetInt64(int64(40))
                 proof, errProve := bulletproofs.ProveGeneric(bigSecret, params)
                 if errProve == nil {
                         ok, errVerify := proof.Verify()
                         if ok && errVerify == nil {
                                 fmt.Println("ZKP successfully verified.")
                         }
                 }
         }
}
```

### Set Membership

### Boudot's Range Proof



## Contributing

### Git hook

To ensure the quality of our project, we run certain checks in out CI pipeline. 
To prevent a longer feedback loop (waiting for CI results), we also enable a git pre-push hook that runs most checks locally.

In the pre-push hook, we want to run the following:

* golangci-lint
* errcheck
* tests

Please create a file called `.git/hooks/pre-push` in the project directory, make it executable and put the following in it:

```$bash
#!/usr/bin/env bash

cd $(git rev-parse --show-toplevel)
.bin/check.sh
```

It runs the same checks as our CI pipeline.

Prerequisites: 

* have golangci-lint installed: `go get -u github.com/golangci/golangci-lint/cmd/golangci-lint` 
* have errcheck installed: `go get -u github.com/kisielk/errcheck`

If you want, you can create a hook for pre-commit as well that does the same: just symlink `.git/hooks/pre-commit` to `.git/hooks/pre-push`.
Then these checks will be executed on every local commit.
