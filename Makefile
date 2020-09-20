.PHONY= all

all: unit-test cover

unit-test:
	@scripts/test.sh

cover:
	go test -coverprofile cover.out ./pkg/...
	go tool cover -html=cover.out