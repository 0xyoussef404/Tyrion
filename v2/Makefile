BINARY := tyrion
GOFLAGS := -mod=mod

.PHONY: build test vet run clean install

build:
	GOFLAGS=$(GOFLAGS) go build -o $(BINARY) ./cmd/tyrion

test:
	GOFLAGS=$(GOFLAGS) go test ./...

vet:
	GOFLAGS=$(GOFLAGS) go vet ./...

run: build
	./$(BINARY) $(ARGS)

install: build
	install -m 0755 $(BINARY) $(HOME)/go/bin/$(BINARY)

clean:
	rm -f $(BINARY)
