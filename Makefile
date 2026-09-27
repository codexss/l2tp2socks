GO ?= go

.PHONY: build test vet clean
build:
	mkdir -p build
	$(GO) build -trimpath -ldflags "-s -w" -o build/l2tp2socks ./cmd/l2tp2socks

test:
	$(GO) test ./...
	$(GO) test github.com/bclswl0827/govpn/protocols/l2tp/...

vet:
	$(GO) vet ./...

clean:
	$(RM) -r build
