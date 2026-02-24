BINDIR := bin

.PHONY: all build build-agent build-server build-authkey test lint clean checksums

all: build

build: build-agent build-server build-authkey

build-agent:
	go build -o $(BINDIR)/nodeattestor-tailscale-agent ./cmd/agent/

build-server:
	go build -o $(BINDIR)/nodeattestor-tailscale-server ./cmd/server/

build-authkey:
	go build -o $(BINDIR)/ts-authkey ./cmd/ts-authkey/

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -rf $(BINDIR)

checksums: build
	cd $(BINDIR) && shasum -a 256 * > checksums.txt
