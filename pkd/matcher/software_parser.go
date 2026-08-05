package matcher

import (
	"encoding/json"

	"nvd-engine/pkd/models"

	"github.com/google/uuid"
)

// parseSoftwareTargets extracts TargetItem entries from installed_software JSONB.
//
// Pipeline stage 2b: Called by fetchServerAssets and fetchEndpointAssets
// (fetcher.go) to transform the installed_software JSONB column into
// matchable TargetItems.
//
// The JSONB is expected to be a map of software name → version
// (e.g. {"nginx": "1.18.0", "openssl": "3.0.1"}). Vendor is left empty
// because it is not present in the data; the matcher relies on the
// product name for CVE lookup.
//
// ownerEmail, hostname, and ipAddress are carried through to the resulting
// TargetItems for the ticket and email notification stages.
func parseSoftwareTargets(assetID uuid.UUID, assetType string, rawSoftware []byte, ownerEmail, hostname, ipAddress string) []models.TargetItem {
	if rawSoftware == nil {
		return nil
	}

	var list []models.TargetItem

	// NEW: Try map of strings (key = name, value = version)
	var strMap map[string]string
	if err := json.Unmarshal(rawSoftware, &strMap); err == nil {
		for name, version := range strMap {
			// Infer vendor from name (optional) or leave empty
			vendor := ""
			// You could add heuristics, e.g., if strings.Contains(name, "VMware") -> vendor="vmware"
			list = append(list, models.TargetItem{
				AssetID:    assetID,
				AssetType:  assetType,
				Vendor:     vendor,
				Product:    name,
				Version:    version,
				OwnerEmail: ownerEmail,
				Hostname:   hostname,
				IPAddress:  ipAddress,
			})
		}
		return list
	}

	return nil
}
