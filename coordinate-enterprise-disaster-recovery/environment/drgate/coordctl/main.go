package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"drcoord/wavesync/drill"
)

type manifest struct {
	Drills []string `json:"drills"`
}

func main() {
	fixtureDir := "/app/dc_drills"
	manifestPath := filepath.Join(fixtureDir, "manifest.json")
	outPath := "/app/build/disaster_recovery_report.json"

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read manifest: %v\n", err)
		os.Exit(1)
	}
	var man manifest
	if err := json.Unmarshal(raw, &man); err != nil {
		fmt.Fprintf(os.Stderr, "parse manifest: %v\n", err)
		os.Exit(1)
	}

	report := drill.Report{Drills: make([]drill.DrillOut, 0, len(man.Drills))}
	for _, id := range man.Drills {
		path := filepath.Join(fixtureDir, id+".json")
		sc, err := drill.LoadDrill(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load %s: %v\n", path, err)
			os.Exit(1)
		}
		report.Drills = append(report.Drills, drill.Analyze(sc))
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
}
