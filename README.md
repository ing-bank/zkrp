# ING ZKP SDK FTW




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
