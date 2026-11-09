package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"huntsig/triageprio/rank"
)

type catalog struct {
	Windows []string `json:"windows"`
}

func main() {
	fixtureDir := "/app/hunt_captures"
	catalogPath := filepath.Join(fixtureDir, "catalog.json")
	outPath := "/app/build/threat_admission_report.json"

	raw, err := os.ReadFile(catalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read catalog: %v\n", err)
		os.Exit(1)
	}
	var cat catalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		fmt.Fprintf(os.Stderr, "parse catalog: %v\n", err)
		os.Exit(1)
	}

	report := rank.Report{Windows: make([]rank.WindowOut, 0, len(cat.Windows))}
	for _, id := range cat.Windows {
		path := filepath.Join(fixtureDir, id+".json")
		win, err := rank.LoadWindow(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load %s: %v\n", path, err)
			os.Exit(1)
		}
		report.Windows = append(report.Windows, rank.AnalyzeWindow(win))
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
