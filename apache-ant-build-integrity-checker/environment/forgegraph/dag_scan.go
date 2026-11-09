package forgegraph

import (
	"encoding/xml"
	"os"
	"strings"

	"antintegrity/auditmodel"
)

type antProjectXML struct {
	Name       string           `xml:"name,attr"`
	Properties []antPropertyXML `xml:"property"`
	Targets    []antTargetXML   `xml:"target"`
}

type antPropertyXML struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type antTargetXML struct {
	Name    string `xml:"name,attr"`
	Depends string `xml:"depends,attr"`
}

func Inspect(path string, contract auditmodel.Contract) (auditmodel.Project, []auditmodel.Violation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return auditmodel.Project{}, nil, err
	}
	var raw antProjectXML
	if err := xml.Unmarshal(data, &raw); err != nil {
		return auditmodel.Project{}, nil, err
	}

	project := auditmodel.Project{
		Name:       strings.TrimSpace(raw.Name),
		Targets:    map[string][]string{},
		Properties: map[string]string{},
	}
	// The upgrade left dependency normalization and graph validation disabled.
	return project, nil, nil
}
