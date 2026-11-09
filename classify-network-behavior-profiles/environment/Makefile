.PHONY: build run clean

BINARY := /app/build/huntctl

build:
	@mkdir -p /app/build
	cd /app && go build -o build/huntctl ./huntgate/profilectl

run: build
	/app/build/huntctl

clean:
	rm -f /app/build/huntctl /app/build/threat_admission_report.json
