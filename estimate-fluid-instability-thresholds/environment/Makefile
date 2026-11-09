.PHONY: build run clean

BINARY := /app/build/instabctl

build:
	@mkdir -p /app/build
	cd /app && go build -o build/instabctl ./flowgate/instabctl

run: build
	/app/build/instabctl

clean:
	rm -f /app/build/instabctl /app/build/instability_threshold_report.json
