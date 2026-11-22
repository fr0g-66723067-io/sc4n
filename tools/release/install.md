```sh
# released binary (linux/amd64 shown; all five targets are on the release)
curl -LO https://github.com/fr0g-66723067-io/sc4n/releases/download/v@VERSION@/sc4n_v@VERSION@_linux_amd64
curl -LO https://github.com/fr0g-66723067-io/sc4n/releases/download/v@VERSION@/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
chmod +x sc4n_v@VERSION@_linux_amd64

# from source: Go 1.27.3
go build -o sc4n ./cmd/sc4n
```
