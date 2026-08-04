package models

import (
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

// CveAffected represents a row from the cve_affected table
type CveAffected struct {
	ID            int
	CveID         string
	Vendor        string
	Product       string
	DefaultStatus string
}

// CveVersion represents a row from the cve_versions table
type CveVersion struct {
	ID                 int
	AffectedID         int
	Version            string
	Status             string
	LessThan           string
	LessThanOrEqual    string
	GreaterThan        string
	GreaterThanOrEqual string
	VersionType        string
}

// AffectedAssetFinding represents a matched CVE for an asset to be inserted into affected_assets
type AffectedAssetFinding struct {
	AssetID   uuid.UUID
	CveID     string
	CvssScore float64
	Severity  string
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
