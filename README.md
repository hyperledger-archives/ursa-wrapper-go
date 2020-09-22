[![Release](https://img.shields.io/github/release/hyperledger/ursa-wrapper-go.svg?style=flat-square)](https://github.com/hyperledger/ursa-wrapper-go/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/hyperledger/ursa-wrapper-go/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/hyperledger/ursa-wrapper-go)

[![codecov](https://codecov.io/gh/hyperledger/ursa-wrapper-go/branch/main/graph/badge.svg?token=dXh8Imy2PO)](https://codecov.io/gh/hyperledger/ursa-wrapper-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/hyperledger/ursa-wrapper-go)](https://goreportcard.com/report/github.com/hyperledger/ursa-wrapper-go)

## ursa-wrapper-go 

- Ursa Wrapper Go requires the [Ursa](https://github.com/hyperledger/ursa) shared library to be installed (eg: /usr/local/lib), and `ursa-wrapper-go.sh` to be sourced. 

```shell script
source ursa-wrapper-go.sh
```
    
#### Development
- `make test` to run unit tests 
    
#### Requirements
- Golang >= `1.14.4` and CGO enabled.