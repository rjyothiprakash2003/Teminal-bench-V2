package propseal

import "antintegrity/auditmodel"

func Resolve(
	xmlProperties map[string]string,
	layers []auditmodel.PropertyLayer,
	required map[string]string,
) ([]auditmodel.PropertyResult, []auditmodel.Violation) {
	// Apache Ant properties are immutable after their first assignment. The
	// resolver was accidentally replaced with a last-write-wins implementation.
	return []auditmodel.PropertyResult{}, nil
}
