PROGNM := sbctl
PREFIX := /usr/local
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib
SHRDIR := $(PREFIX)/share
DOCDIR := $(PREFIX)/share/doc
MANDIR := $(PREFIX)/share/man
MANS = $(basename $(wildcard docs/*.txt))

GOFLAGS ?= -buildmode=pie -trimpath

TAG = $(shell git describe --abbrev=0 --tags)

all: man build
build: sbctl
man: $(MANS)
$(MANS):

docs/sbctl.%: docs/sbctl.%.txt docs/asciidoc.conf
	a2x --no-xmllint --asciidoc-opts="-f docs/asciidoc.conf" -d manpage -f manpage -D docs $<

.PHONY: sbctl
sbctl:
	go build -o $@ ./cmd/$@

.PHONY: completions
completions: sbctl
	./sbctl completion bash | install -D /dev/stdin contrib/completions/bash-completion/completions/sbctl
	./sbctl completion zsh | install -D /dev/stdin contrib/completions/zsh/site-functions/_sbctl
	./sbctl completion fish | install -D /dev/stdin contrib/completions/fish/vendor_completions.d/sbctl.fish

install: sbctl completions man
	install -Dm755 sbctl -t '$(DESTDIR)$(BINDIR)'
	for manfile in $(MANS); do \
		install -Dm644 "$$manfile" -t '$(DESTDIR)$(MANDIR)/man'"$${manfile##*.}"; \
	done;
	install -Dm644 contrib/completions/bash-completion/completions/sbctl '$(DESTDIR)$(SHRDIR)/bash-completion/completions/sbctl'
	install -Dm644 contrib/completions/zsh/site-functions/_sbctl '$(DESTDIR)$(SHRDIR)/zsh/site-functions/_sbctl'
	install -Dm644 contrib/completions/fish/vendor_completions.d/sbctl.fish '$(DESTDIR)$(SHRDIR)/fish/vendor_completions.d/sbctl.fish'
	install -Dm755 contrib/kernel-install/91-sbctl.install '$(DESTDIR)$(LIBDIR)/kernel/install.d/91-sbctl.install'
	install -Dm644 LICENSE -t '$(DESTDIR)$(SHRDIR)/licenses/$(PROGNM)'

.PHONY: release
release:
	mkdir -p releases
	git archive --prefix=${PROGNM}-${TAG}/ -o releases/${PROGNM}-${TAG}.tar.gz ${TAG};
	gpg --detach-sign -o releases/${PROGNM}-${TAG}.tar.gz.sig releases/${PROGNM}-${TAG}.tar.gz
	gh release upload ${TAG} releases/${PROGNM}-${TAG}.tar.gz.sig releases/${PROGNM}-${TAG}.tar.gz ${TAG}

.PHONY: push-aur
push-aur:
	git subtree push -P "contrib/aur/sbctl-git" aur:sbctl-git.git master

clean:
	rm -f $(MANS)
	rm -f sbctl

.PHONY: lint
lint:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@v0.4.0 ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: prepare-integration
prepare-integration:
	docker run --privileged -v ${PWD}/tests/:/workdir -w /workdir archlinux ./make_image.sh

.PHONY: integration
integration:
	go test -v tests/integration_test.go

.PHONY: local-aur
.ONESHELL:
local-aur:
	cd ./contrib/aur/sbctl-git
	mkdir -p ./src
	ln -srfT $(CURDIR) ./src/sbctl
	makepkg --holdver --syncdeps --noextract --force
