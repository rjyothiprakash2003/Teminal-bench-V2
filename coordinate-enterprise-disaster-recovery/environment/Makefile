.PHONY: build run clean

BINARY := /app/build/drcoord

build:
	@mkdir -p /app/build
	cd /app && go build -o build/drcoord ./drgate/coordctl

run: build
	/app/build/drcoord

clean:
	rm -f /app/build/drcoord /app/build/disaster_recovery_report.json
