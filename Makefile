BINARY  := perfectimage
PKG     := ./cmd/perfectimage
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
export CGO_ENABLED := 0

.PHONY: all build build-linux build-windows test race vet fmt fmt-check vuln ci run clean

all: ci build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

build-linux:
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 $(PKG)

build-windows:
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe $(PKG)

test:
	(umask 077; go test -count=1 ./...)

race:
	(umask 077; go test -race -count=1 ./...)

vet:
	go vet ./...
	GOOS=windows GOARCH=amd64 go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Everything CI runs (except govulncheck, which needs network).
ci: fmt-check vet race
	go build ./...
	GOOS=windows GOARCH=amd64 go build ./...

run:
	go run $(PKG) serve --config config.example.yaml

clean:
	rm -rf bin dist data
