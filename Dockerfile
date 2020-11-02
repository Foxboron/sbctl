FROM golang:1.15-buster
WORKDIR $GOPATH/src/github.com/Foxboron/sbctl
COPY . .

# Install dependencies
RUN go get honnef.co/go/tools/cmd/staticcheck@2020.1.6

# Run code linters
RUN go vet ./...
RUN staticcheck ./...

# Run test suite
RUN go test -v ./...

# Build binaries
RUN go install
