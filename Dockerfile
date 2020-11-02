FROM golang:1.15-buster
WORKDIR $GOPATH/src/github.com/Foxboron/sbctl
COPY . .

# Install dependencies and run code linters
RUN make lint

# Run test suite
RUN make test

# Build binaries
RUN make sbctl
