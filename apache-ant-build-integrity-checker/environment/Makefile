.PHONY: build verify clean

BINARY := /app/build/antlock
PROJECT := /app/ember_workcell/ember_pipeline.xml
CONTRACT := /app/ember_workcell/ember_integrity_contract.json
EVIDENCE := /app/ember_workcell/ember_execution_evidence.json
DECISION := /app/build/ember_gate_decision.json

build:
	@mkdir -p /app/build
	cd /app && go build -trimpath -o $(BINARY) ./antlock/cmd/antlock

verify: build
	$(BINARY) gate -project $(PROJECT) -contract $(CONTRACT) -evidence $(EVIDENCE) -decision $(DECISION)

clean:
	rm -f $(BINARY) $(DECISION)
