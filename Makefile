BIN      := clotr
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
GOFLAGS  := -trimpath
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
DIST     := dist
REPO     := agardenat/clotr
NFPM     ?= go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0

.PHONY: build test vet cross dist notes formula clean

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(BIN) ./cmd/clotr

test:
	go test -race ./...

vet:
	go vet ./...

cross:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(BIN)-$$os-$$arch ./cmd/clotr || exit 1; \
	done

dist: cross
	rm -rf $(DIST) && mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; d=$$(mktemp -d); \
		cp bin/$(BIN)-$$os-$$arch $$d/$(BIN) && cp LICENSE README.md $$d/ && \
		tar --owner=0 --group=0 --numeric-owner -C $$d -czf $(DIST)/$(BIN)_$(VERSION:v%=%)_$${os}_$${arch}.tar.gz $(BIN) LICENSE README.md || exit 1; \
		rm -rf $$d; \
	done
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; [ "$$os" = linux ] || continue; \
		for f in deb rpm; do \
			PKG_ARCH=$$arch VERSION=$(VERSION:v%=%) $(NFPM) package --config packaging/nfpm.yaml --packager $$f --target $(DIST)/ || exit 1; \
		done; \
	done
	cd $(DIST) && sha256sum *.tar.gz *.deb *.rpm > SHA256SUMS

notes:
	@awk -v h='## [$(VERSION:v%=%)]' 'index($$0, h) == 1 { p = 1; f = 1; next } /^## \[/ { p = 0 } p { print } END { exit !f }' CHANGELOG.md

formula:
	@v='$(VERSION:v%=%)'; \
	sum() { awk -v f="$(BIN)_$${v}_$$1.tar.gz" '$$2 == f { print $$1; n++ } END { exit n != 1 }' $(DIST)/SHA256SUMS; }; \
	s1=$$(sum darwin_arm64) && s2=$$(sum darwin_amd64) && s3=$$(sum linux_arm64) && s4=$$(sum linux_amd64) && \
	sed -e "s|@VERSION@|$$v|g" -e "s|@REPO@|$(REPO)|g" \
		-e "s|@SHA256_DARWIN_ARM64@|$$s1|" -e "s|@SHA256_DARWIN_AMD64@|$$s2|" \
		-e "s|@SHA256_LINUX_ARM64@|$$s3|" -e "s|@SHA256_LINUX_AMD64@|$$s4|" \
		packaging/homebrew/clotr.rb.in > $(DIST)/$(BIN).rb

clean:
	rm -rf bin $(DIST)
