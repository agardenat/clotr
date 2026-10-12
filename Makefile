BIN      := clotr
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
GOFLAGS  := -trimpath
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
DIST     := dist
REPO     := agardenat/clotr
BOTTLE_MACOS := ventura
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
		os=$${p%/*}; arch=$${p#*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(BIN)-$$os-$$arch$$ext ./cmd/clotr || exit 1; \
	done

dist: cross
	rm -rf $(DIST) && mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; d=$$(mktemp -d); name=$(BIN)_$(VERSION:v%=%)_$${os}_$${arch}; \
		cp LICENSE README.md $$d/ || exit 1; \
		if [ "$$os" = windows ]; then \
			cp bin/$(BIN)-$$os-$$arch.exe $$d/$(BIN).exe && (cd $$d && zip -q -X $(CURDIR)/$(DIST)/$$name.zip $(BIN).exe LICENSE README.md) || exit 1; \
		else \
			cp bin/$(BIN)-$$os-$$arch $$d/$(BIN) && tar --owner=0 --group=0 --numeric-owner -C $$d -czf $(DIST)/$$name.tar.gz $(BIN) LICENSE README.md || exit 1; \
			tag=$$(case $$p in darwin/arm64) echo arm64_$(BOTTLE_MACOS);; darwin/amd64) echo $(BOTTLE_MACOS);; linux/arm64) echo arm64_linux;; linux/amd64) echo x86_64_linux;; esac); \
			b=$$(mktemp -d) && install -D -m 755 bin/$(BIN)-$$os-$$arch $$b/$(BIN)/$(VERSION:v%=%)/bin/$(BIN) && \
			tar --owner=0 --group=0 --numeric-owner -C $$b -czf $(DIST)/$(BIN)-$(VERSION:v%=%).$$tag.bottle.tar.gz $(BIN) && rm -rf $$b || exit 1; \
		fi; \
		rm -rf $$d; \
	done
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; [ "$$os" = linux ] || continue; \
		for f in deb rpm; do \
			PKG_ARCH=$$arch VERSION=$(VERSION:v%=%) $(NFPM) package --config packaging/nfpm.yaml --packager $$f --target $(DIST)/ || exit 1; \
		done; \
	done
	cd $(DIST) && sha256sum *.tar.gz *.zip *.deb *.rpm > SHA256SUMS

notes:
	@awk -v h='## [$(VERSION:v%=%)]' 'index($$0, h) == 1 { p = 1; f = 1; next } /^## \[/ { p = 0 } p { print } END { exit !f }' CHANGELOG.md

formula:
	@v='$(VERSION:v%=%)'; \
	sum() { awk -v f="$(BIN)_$${v}_$$1.tar.gz" '$$2 == f { print $$1; n++ } END { exit n != 1 }' $(DIST)/SHA256SUMS; }; \
	bottle() { awk -v f="$(BIN)-$${v}.$$1.bottle.tar.gz" '$$2 == f { print $$1; n++ } END { exit n != 1 }' $(DIST)/SHA256SUMS; }; \
	s1=$$(sum darwin_arm64) && s2=$$(sum darwin_amd64) && s3=$$(sum linux_arm64) && s4=$$(sum linux_amd64) && \
	b1=$$(bottle arm64_$(BOTTLE_MACOS)) && b2=$$(bottle $(BOTTLE_MACOS)) && b3=$$(bottle arm64_linux) && b4=$$(bottle x86_64_linux) && \
	sed -e "s|@VERSION@|$$v|g" -e "s|@REPO@|$(REPO)|g" -e "s|@BOTTLE_MACOS@|$(BOTTLE_MACOS)|g" \
		-e "s|@SHA256_DARWIN_ARM64@|$$s1|" -e "s|@SHA256_DARWIN_AMD64@|$$s2|" \
		-e "s|@SHA256_LINUX_ARM64@|$$s3|" -e "s|@SHA256_LINUX_AMD64@|$$s4|" \
		-e "s|@BOTTLE_DARWIN_ARM64@|$$b1|" -e "s|@BOTTLE_DARWIN_AMD64@|$$b2|" \
		-e "s|@BOTTLE_LINUX_ARM64@|$$b3|" -e "s|@BOTTLE_LINUX_AMD64@|$$b4|" \
		packaging/homebrew/clotr.rb.in > $(DIST)/$(BIN).rb

clean:
	rm -rf bin $(DIST)
