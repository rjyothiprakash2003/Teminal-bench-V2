package auditmodel

type Contract struct {
	RequiredTargets    []string            `json:"required_targets"`
	RequiredEdges      map[string][]string `json:"required_edges"`
	RequiredProperties map[string]string   `json:"required_properties"`
	RequiredArtifacts  []ArtifactRule      `json:"required_artifacts"`
	IncrementalTargets []string            `json:"incremental_targets"`
	Package            PackageRule         `json:"package"`
	SHA256Pattern      string              `json:"sha256_pattern"`
	ViolationCodes     map[string]string   `json:"violation_codes"`
	DetailRules        map[string]string   `json:"detail_rules"`
	CoFireExamples     map[string][]string `json:"co_fire_examples"`
}

type ArtifactRule struct {
	Path     string `json:"path"`
	Producer string `json:"producer"`
}

type PackageRule struct {
	RequiredEntries                []string `json:"required_entries"`
	Epoch                          int64    `json:"epoch"`
	Mode                           string   `json:"mode"`
	MinimumUniqueOperatingSystems  int      `json:"minimum_unique_operating_systems"`
}

type Evidence struct {
	PropertyLayers []PropertyLayer    `json:"property_layers"`
	Artifacts      []ArtifactEvidence `json:"artifacts"`
	Incremental    []IncrementalRun   `json:"incremental"`
	Packages       []PackageEvidence  `json:"packages"`
}

type PropertyLayer struct {
	Source string            `json:"source"`
	Values map[string]string `json:"values"`
}

type ArtifactEvidence struct {
	Path       string `json:"path"`
	Producer   string `json:"producer"`
	SHA256     string `json:"sha256"`
	SidecarSHA string `json:"sidecar_sha256"`
}

type IncrementalRun struct {
	Target       string `json:"target"`
	InputBefore  string `json:"input_before"`
	InputAfter   string `json:"input_after"`
	OutputBefore string `json:"output_before"`
	OutputAfter  string `json:"output_after"`
	Executed     bool   `json:"executed"`
}

type PackageEvidence struct {
	OS            string         `json:"os"`
	ArchiveSHA256 string         `json:"archive_sha256"`
	Entries       []PackageEntry `json:"entries"`
}

type PackageEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
	MTime  int64  `json:"mtime"`
}

type Project struct {
	Name       string
	Targets    map[string][]string
	Properties map[string]string
}

type Violation struct {
	Code    string `json:"code"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
}

type PropertyResult struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

type TargetResult struct {
	Name         string   `json:"name"`
	Dependencies []string `json:"dependencies"`
}

type GateDecision struct {
	Project    string           `json:"project"`
	Verdict    string           `json:"verdict"`
	Targets    []TargetResult   `json:"targets"`
	Properties []PropertyResult `json:"properties"`
	Violations []Violation      `json:"violations"`
}
