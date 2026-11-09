package analyzer

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
)

type Report struct {
	SchemaVersion         string                `json:"schema_version"`
	Packages              []Package             `json:"packages"`
	Edges                 []Edge                `json:"edges"`
	Conflicts             []Conflict            `json:"conflicts"`
	UnusedDependencies    []UnusedDependency    `json:"unused_dependencies"`
	SourceInconsistencies []SourceInconsistency `json:"source_inconsistencies"`
	Cycles                [][]string            `json:"cycles"`
	LockfileIssues        []LockfileIssue       `json:"lockfile_issues"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

type Edge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Constraint string `json:"constraint"`
	Scope      string `json:"scope"`
	Source     string `json:"source"`
}

type Conflict struct {
	Package      string   `json:"package"`
	Constraints  []string `json:"constraints"`
	RequiredBy   []string `json:"required_by"`
}

type UnusedDependency struct {
	Package    string `json:"package"`
	Dependency string `json:"dependency"`
}

type SourceInconsistency struct {
	Dependency string   `json:"dependency"`
	Sources    []string `json:"sources"`
	DeclaredBy []string `json:"declared_by"`
}

type LockfileIssue struct {
	Package    string `json:"package"`
	Dependency string `json:"dependency"`
	Kind       string `json:"kind"`
	Expected   string `json:"expected"`
	Actual     string `json:"actual"`
}

func Run(args []string) error {
	if len(args) == 0 || args[0] != "analyze" {
		return errors.New("usage: pubguard analyze --root DIRECTORY --output FILE")
	}
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	root := flags.String("root", "", "monorepository root")
	output := flags.String("output", "", "JSON report path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *root == "" || *output == "" {
		return errors.New("both --root and --output are required")
	}

	// The implementation is intentionally incomplete. Discover and parse the
	// workspace, perform every validation, sort every collection, then replace
	// this empty report.
	report := Report{
		SchemaVersion:         "1",
		Packages:              []Package{},
		Edges:                 []Edge{},
		Conflicts:             []Conflict{},
		UnusedDependencies:    []UnusedDependency{},
		SourceInconsistencies: []SourceInconsistency{},
		Cycles:                [][]string{},
		LockfileIssues:        []LockfileIssue{},
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(*output, data, 0o644)
}
