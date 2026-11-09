package reportwire

import (
	"encoding/json"
	"os"

	"antintegrity/auditmodel"
)

func Write(path string, decision auditmodel.GateDecision) error {
	data, err := json.MarshalIndent(decision, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
