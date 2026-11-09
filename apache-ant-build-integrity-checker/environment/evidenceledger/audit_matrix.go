package evidenceledger

import "antintegrity/auditmodel"

func Reconcile(contract auditmodel.Contract, evidence auditmodel.Evidence) []auditmodel.Violation {
	// Artifact, incremental, and cross-platform package evidence checks must be
	// restored here without trusting values from the editable project.
	return nil
}
