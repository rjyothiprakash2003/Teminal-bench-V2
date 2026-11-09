package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"realmshadow/pkg/trustmesh"
	"realmshadow/pkg/wireajn"
)

type trustIndex struct {
	Scenarios []string `json:"scenarios"`
}

func pruneOutbox() error {
	keep := map[string]struct{}{
		"realmshadow":                      {},
		"trust_mesh_audit.json": {},
	}
	entries, err := os.ReadDir("/app/outbox")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if _, ok := keep[entry.Name()]; ok {
			continue
		}
		path := "/app/outbox/" + entry.Name()
		if entry.IsDir() {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
			continue
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
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
		journalPath := dataDir + "/" + id + "/federation_trace.ajn"
		sc, err := trustmesh.LoadScenario(cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load %s: %v\n", cfgPath, err)
			os.Exit(1)
		}
		events, journalStats, err := wireajn.Decode(journalPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode %s: %v\n", journalPath, err)
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
	if err := pruneOutbox(); err != nil {
		fmt.Fprintf(os.Stderr, "prune outbox: %v\n", err)
		os.Exit(1)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	// Encode already appends a trailing newline.
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
}