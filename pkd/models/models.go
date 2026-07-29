package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// TargetItem represents an asset fetched from NeonDB for CVE matching
type TargetItem struct {
	AssetID     uuid.UUID
	AssetType   string
	Vendor      string
	Product     string
	Version     string
	CpeCriteria string
}

// InstalledSoftwareItem represents a software entry from installed_software JSONB
type InstalledSoftwareItem struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
}

// NvdRawJson represents the top-level structure of a CVE entry from nvd_cves.raw_json
type NvdRawJson struct {
	ID             string          `json:"id"`
	Configurations []NvdConfigNode `json:"configurations"`
	Metrics        NvdMetrics      `json:"metrics"`
}

// NvdConfigNode represents a configuration node in the CVE JSON
type NvdConfigNode struct {
	Nodes []NvdNode `json:"nodes"`
	Negate bool     `json:"negate"`
	Operator string `json:"operator"`
}

// NvdNode represents a node within configurations
type NvdNode struct {
	CpeMatch []CpeMatch `json:"cpeMatch"`
	Negate   bool       `json:"negate"`
	Operator string     `json:"operator"`
}

// CpeMatch represents a CPE match entry
type CpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// NvdMetrics holds CVSS metric versions
type NvdMetrics struct {
	CvssMetricV31 []CvssMetricV31 `json:"cvssMetricV31"`
}

// CvssMetricV31 represents a CVSS v3.1 metric
type CvssMetricV31 struct {
	Type      string   `json:"type"`
	Source    string   `json:"source"`
	CvssData  CvssData `json:"cvssData"`
}

// CvssData holds the CVSS score details
type CvssData struct {
	Version       string  `json:"version"`
	BaseScore     float64 `json:"baseScore"`
	BaseSeverity  string  `json:"baseSeverity"`
	VectorString  string  `json:"vectorString"`
}

// AffectedAssetFinding represents a matched CVE for an asset to be inserted into affected_assets
type AffectedAssetFinding struct {
	AssetID   uuid.UUID
	CveID     string
	CvssScore float64
	Severity  string
}

// Helper to unmarshal NvdRawJson from raw JSON bytes
func UnmarshalNvdRawJson(data []byte) (*NvdRawJson, error) {
	var raw NvdRawJson
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return &raw, nil
}

// VersionCompareResult is used for version comparison logic
type VersionCompareResult int

const (
	VersionLess    VersionCompareResult = -1
	VersionEqual   VersionCompareResult = 0
	VersionGreater VersionCompareResult = 1
	VersionInvalid VersionCompareResult = -2
)

// InsertAffectedAssetParams holds parameters for inserting into affected_assets
type InsertAffectedAssetParams struct {
	AssetID   uuid.UUID
	CveID     string
	CvssScore float64
	Severity  string
	MatchedAt time.Time
}