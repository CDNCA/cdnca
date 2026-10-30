# Tests that need local containers

## SSH remote node install (`services/control-api/internal/nodesshinstall`)

`TestSSHInstallAgainstRealSSHD` logs in to a throwaway sshd container (started with `docker run --rm`, published on
127.0.0.1 only) and runs the install command against a stand-in `curl` that only records its arguments. No real server
is contacted. The test skips when Docker or the image is missing.

```sh
make test-sshd-image                      # docker build -t cdnca-test-sshd:ge-nodes …/testdata/sshd
TEST_DATABASE_URL=postgres://… make test-ssh-install
docker rmi cdnca-test-sshd:ge-nodes       # when done
```

Not wired into CI.
