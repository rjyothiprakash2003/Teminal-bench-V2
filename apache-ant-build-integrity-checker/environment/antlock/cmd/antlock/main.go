package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"antintegrity/auditmodel"
	"antintegrity/evidenceledger"
	"antintegrity/forgegraph"
	"antintegrity/propseal"
	"antintegrity/reportwire"
)

func loadJSON(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "gate" {
		fmt.Fprintln(os.Stderr, "usage: antlock gate -project FILE -contract FILE -evidence FILE -decision FILE")
		os.Exit(2)
	}

	flags := flag.NewFlagSet("gate", flag.ExitOnError)
	projectPath := flags.String("project", "", "Apache Ant project XML")
	contractPath := flags.String("contract", "", "integrity contract JSON")
	evidencePath := flags.String("evidence", "", "execution evidence JSON")
	decisionPath := flags.String("decision", "", "output gate decision JSON")
	_ = flags.Parse(os.Args[2:])
	if *projectPath == "" || *contractPath == "" || *evidencePath == "" || *decisionPath == "" {
		fmt.Fprintln(os.Stderr, "all gate paths are required")
		os.Exit(2)
	}

	var contract auditmodel.Contract
	var evidence auditmodel.Evidence
	if err := loadJSON(*contractPath, &contract); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := loadJSON(*evidencePath, &evidence); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	project, graphViolations, err := forgegraph.Inspect(*projectPath, contract)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	properties, propertyViolations := propseal.Resolve(
		project.Properties,
		evidence.PropertyLayers,
		contract.RequiredProperties,
	)
	violations := append(graphViolations, propertyViolations...)
	violations = append(violations, evidenceledger.Reconcile(contract, evidence)...)

	targets := make([]auditmodel.TargetResult, 0, len(project.Targets))
	for name, dependencies := range project.Targets {
		targets = append(targets, auditmodel.TargetResult{Name: name, Dependencies: dependencies})
	}
	verdict := "RELEASABLE"
	if len(violations) != 0 {
		verdict = "BLOCKED"
	}
	decision := auditmodel.GateDecision{
		Project:    project.Name,
		Verdict:    verdict,
		Targets:    targets,
		Properties: properties,
		Violations: violations,
	}
	if err := reportwire.Write(*decisionPath, decision); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
