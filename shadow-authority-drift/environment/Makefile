.PHONY: build run clean

BINARY := /app/outbox/realmshadow

build:
	@mkdir -p /app/outbox
	cd /app && /usr/local/go/bin/go build -o outbox/realmshadow ./svc/realmshadow

run: build
	/app/outbox/realmshadow

clean:
	rm -f /app/outbox/realmshadow /app/outbox/trust_mesh_audit.json
