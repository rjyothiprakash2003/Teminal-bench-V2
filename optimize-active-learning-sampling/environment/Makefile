.PHONY: build run clean

BINARY := /app/build/alsctl

build:
	@mkdir -p /app/build
	cd /app && go build -o build/alsctl ./samplegate/alsctl

run: build
	/app/build/alsctl

clean:
	rm -f /app/build/alsctl /app/build/active_learning_report.json
