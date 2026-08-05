// Package models defines the shared data structures used across the CVE matcher pipeline.
//
// These types flow through the pipeline stages:
//   - TargetItem: produced by the fetch stage (matcher/fetcher.go), consumed by the matching stage
//   - CveVersion: produced by the CVE lookup stage (matcher/cve_lookup.go), consumed by version matching (matcher/version.go)
//   - AffectedAssetFinding: produced by the matching stage (matcher/matcher.go), consumed by the write stage (matcher/writer.go)
//   - CveTicket: produced by the ticket stage (matcher/ticket.go), consumed by the notification stage (matcher/notifier.go)
//   - VersionCompareResult: used by version comparison logic (matcher/version.go)
package models

import (
	"time"

	"github.com/google/uuid"
)

// TargetItem represents an asset fetched from NeonDB for CVE matching.
// It is the normalized form of an asset (network device, server OS,
// endpoint OS, or installed software) that the matcher can query CVEs against.
type TargetItem struct {
	AssetID     uuid.UUID
	AssetType   string
	Vendor      string
	Product     string
	Version     string
	CpeCriteria string
	OwnerEmail  string
	Hostname    string
	IPAddress   string
}

// InstalledSoftwareItem represents a software entry from installed_software JSONB.
// Note: currently unused by the pipeline — parseSoftwareTargets (matcher/software_parser.go)
// reads the JSONB directly as a map[string]string instead.
type InstalledSoftwareItem struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
}

// CveAffected represents a row from the cve_affected table in NvdDB.
// Note: currently unused — the lookup queries (matcher/cve_lookup.go)
// scan rows directly into CveLookupResult instead.
type CveAffected struct {
	ID            int
	CveID         string
	Vendor        string
	Product       string
	DefaultStatus string
}

// CveVersion represents a version constraint for a CVE from the cve_versions table.
// It is used by the version matching logic (matcher/version.go) to determine
// whether a specific asset version is affected by a CVE.
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

// AffectedAssetFinding represents a matched CVE for an asset.
// It is produced by the matching stage (matcher/matcher.go) and
// inserted into the affected_assets table by the write stage (matcher/writer.go).
// Product holds the name of the software/product that caused the CVE match.
type AffectedAssetFinding struct {
	AssetID   uuid.UUID
	CveID     string
	Product   string
	Version   string
	CvssScore float64
	Severity  string

	// Enrichment fields populated during ticket creation (matcher/ticket.go)
	OwnerEmail string
	Hostname   string
	IPAddress  string
}

// CveTicket represents a ticket row to be inserted into the cve_ticket table.
// Produced by the ticket stage (matcher/ticket.go) and consumed by the
// notification stage (matcher/notifier.go) for email dispatch.
type CveTicket struct {
	AssetID     uuid.UUID
	CveID       string
	Status      string
	Priority    string
	AssignedTo  string
	Description string
	DueDate     time.Time
	CreatedAt   time.Time

	// Enrichment fields for email (not persisted to DB)
	OwnerEmail string
	Hostname   string
	IPAddress  string
	Product    string
	Version    string
	CvssScore  float64
	Severity   string
}

// VersionCompareResult is the result of a version comparison.
// Used by compareVersions (matcher/version.go).
type VersionCompareResult int

const (
	VersionLess    VersionCompareResult = -1
	VersionEqual   VersionCompareResult = 0
	VersionGreater VersionCompareResult = 1
	VersionInvalid VersionCompareResult = -2
)

// InsertAffectedAssetParams holds parameters for inserting into affected_assets.
// Note: currently unused — InsertFindings (matcher/writer.go) builds the
// insert directly from AffectedAssetFinding values.
type InsertAffectedAssetParams struct {
	AssetID   uuid.UUID
	CveID     string
	CvssScore float64
	Severity  string
	MatchedAt time.Time
}
