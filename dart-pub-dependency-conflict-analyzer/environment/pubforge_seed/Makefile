.PHONY: build test clean

build:
	@mkdir -p /app/bin
	go build -trimpath -ldflags="-buildid=" -o /app/bin/pubguard ./cmd/pubguard

test:
	go test ./...

clean:
	rm -f /app/bin/pubguard
