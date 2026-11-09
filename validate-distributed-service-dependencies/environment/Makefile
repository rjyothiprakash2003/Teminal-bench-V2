.PHONY: build run clean

BINARY := /app/build/scorectl

build:
	@mkdir -p /app/build
	cd /app && go build -o build/scorectl ./scoregate/scorectl

run: build
	/app/build/scorectl

clean:
	rm -f /app/build/scorectl /app/build/pairing_class_report.json
