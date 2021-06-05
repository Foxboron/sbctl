PROGNM ?= sbctl
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SHRDIR ?= $(PREFIX)/share
DOCDIR ?= $(PREFIX)/share/doc
MANDIR ?= $(PREFIX)/share/man
MANS = $(basename $(wildcard docs/*.txt))

GOFLAGS ?= -buildmode=pie -trimpath

SOURCES = $(shell go list -f '{{range .GoFiles}}{{$$.Dir}}/{{.}} {{end}}' ./...)

TAG = $(shell git describe --abbrev=0 --tags)

all: man build
build: sbctl
man: $(MANS)
$(MANS):

docs/sbctl.%: docs/sbctl.%.txt docs/asciidoc.conf
	a2x --no-xmllint --asciidoc-opts="-f docs/asciidoc.conf" -d manpage -f manpage -D docs $<

sbctl: $(SOURCES)
	go build ./cmd/$@

install: man
	install -Dm755 sbctl -t $(DESTDIR)$(BINDIR)
	for manfile in $(MANS); do \
		install -Dm644 $$manfile -t $(DESTDIR)$(MANDIR)/man$${manfile##*.}; \
	done;
	install -Dm644 LICENSE -t $(DESTDIR)$(SHRDIR)/licenses/$(PROGNM)

.PHONY: release
release:
	mkdir -p releases
	git archive --prefix=${PROGNM}-${TAG}/ -o releases/${PROGNM}-${TAG}.tar.gz ${TAG};
	gpg --detach-sign -o releases/${PROGNM}-${TAG}.tar.gz.sig releases/${PROGNM}-${TAG}.tar.gz
	hub release create -m "Release: ${TAG}" -a releases/${PROGNM}-${TAG}.tar.gz.sig -a releases/${PROGNM}-${TAG}.tar.gz ${TAG}

.PHONY: push-aur
push-aur:
	git subtree push -P "contrib/aur/sbctl-git" aur:sbctl-git.git master

clean:
	rm -f $(MANS)
	rm -f sbctl

.PHONY: deps
deps:
	go get honnef.co/go/tools/cmd/staticcheck@2020.1.6

.PHONY: lint
lint:
	go vet ./...
	staticcheck ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: integration
integration:
	go test -v tests/integration_test.go
