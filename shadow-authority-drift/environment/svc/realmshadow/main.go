package main

import (
	"encoding/json"
	"fmt"
	"os"

	"realmshadow/pkg/trustmesh"
	"realmshadow/pkg/wireajn"
)

type trustIndex struct {
	Scenarios []string `json:"scenarios"`
}

func main() {
	dataDir := "/app/trustcorpus"
	indexPath := dataDir + "/trust_index.json"
	outPath := "/app/outbox/trust_mesh_audit.json"

	raw, err := os.ReadFile(indexPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read trust index: %v\n", err)
		os.Exit(1)
	}
	var index trustIndex
	if err := json.Unmarshal(raw, &index); err != nil {
		fmt.Fprintf(os.Stderr, "parse trust index: %v\n", err)
		os.Exit(1)
	}

	report := trustmesh.Report{Scenarios: make([]trustmesh.ScenarioOut, 0, len(index.Scenarios))}
	for _, id := range index.Scenarios {
		cfgPath := dataDir + "/" + id + ".json"
		tracePath := dataDir + "/" + id + "/federation_trace.ajn"
		sc, err := trustmesh.LoadScenario(cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load %s: %v\n", cfgPath, err)
			os.Exit(1)
		}
		events, journalStats, err := wireajn.Decode(tracePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode %s: %v\n", tracePath, err)
			os.Exit(1)
		}
		sc.Events = events
		journalOut := trustmesh.JournalOut{
			FormatVersion:   journalStats.FormatVersion,
			RecordsTotal:    journalStats.RecordsTotal,
			RecordsValid:    journalStats.RecordsValid,
			RecordsRejected: journalStats.RecordsRejected,
			DupSeqRejects:   journalStats.DupSeqRejects,
			TruncatedTail:   journalStats.TruncatedTail,
			PayloadBytes:    journalStats.PayloadBytes,
		}
		report.Scenarios = append(report.Scenarios, trustmesh.Analyze(sc, journalOut))
	}

	if err := os.MkdirAll("/app/outbox", 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	enc, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	out := append(enc, '\n')
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
}
