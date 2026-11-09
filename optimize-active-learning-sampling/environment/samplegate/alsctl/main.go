package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"alsbench/pickcore/suite"
)

type manifest struct {
	Suites []string `json:"suites"`
}

func main() {
	fixtureDir := "/app/label_suites"
	manifestPath := filepath.Join(fixtureDir, "manifest.json")
	outPath := "/app/build/active_learning_report.json"

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

	report := suite.Report{Suites: make([]suite.SuiteOut, 0, len(man.Suites))}
	for _, id := range man.Suites {
		path := filepath.Join(fixtureDir, id+".json")
		sc, err := suite.LoadSuite(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load %s: %v\n", path, err)
			os.Exit(1)
		}
		report.Suites = append(report.Suites, suite.Analyze(sc))
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
