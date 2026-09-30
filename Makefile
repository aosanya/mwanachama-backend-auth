.PHONY: build test test-pg vet clean

build:
	go build ./...

test:
	go test ./...

test-pg:
	go test -tags=postgres ./...

vet:
	go vet ./...

clean:
	rm -rf bin/
