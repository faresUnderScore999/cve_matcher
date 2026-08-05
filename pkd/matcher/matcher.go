package matcher

import (
	"context"
	"encoding/json"

	"nvd-engine/pkd/db"
	"nvd-engine/pkd/models"
)

// MatchResult holds a target item and its matching CVE findings.
// Produced by the matching stage and consumed by the write stage.
type MatchResult struct {
	Target   models.TargetItem
	Findings []models.AffectedAssetFinding
}

// MatchBatchTargets matches multiple targets that share the same vendor/product
// against the NVD database using a single query. This is much more efficient
// than querying once per asset.
//
// Pipeline stage 4: This is the main entry point of the matching stage.
// It is called by main.go for each (vendor, product) group.
//
// Flow:
//  1. Lookup CVEs via fetchCvesByVendorProduct (cve_lookup.go)
//  2. Lookup additional CVEs via fetchCvesByCpeTable (cve_lookup.go)
//  3. Merge both result sets via mergeCveResults (cve_lookup.go)
//  4. Match each target in-memory via matchTargetAgainstCves (no DB queries)
func MatchBatchTargets(ctx context.Context, dbs *db.Databases, vendor, product string, targets []models.TargetItem) ([]MatchResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// Query CVEs from the cve_affected/cve_versions tables
	cves, err := fetchCvesByVendorProduct(ctx, dbs, vendor, product)
	if err != nil {
		return nil, err
	}

	// Query CVEs from the cve_cpes table and merge with the first result set
	cpeCves, err := fetchCvesByCpeTable(ctx, dbs, vendor, product)
	if err != nil {
		return nil, err
	}

	cves = mergeCveResults(cves, cpeCves)

	if len(cves) == 0 {
		// No CVEs found for this vendor/product — no findings for any target
		return nil, nil
	}

	// Match each target against the cached CVE results (in-memory, no DB queries)
	var results []MatchResult
	for _, target := range targets {
		findings := matchTargetAgainstCves(target, cves)
		if len(findings) > 0 {
			results = append(results, MatchResult{
				Target:   target,
				Findings: findings,
			})
		}
	}

	return results, nil
}

// matchTargetAgainstCves checks a single target against pre-fetched CVE lookup results.
// No database queries are made — all matching is done in-memory.
//
// Called by MatchBatchTargets for each target in a group.
// Uses isVersionAffected (version.go) for version constraint evaluation
// and extractCvssFromRaw for CVSS score extraction.
func matchTargetAgainstCves(target models.TargetItem, cves []CveLookupResult) []models.AffectedAssetFinding {
	var findings []models.AffectedAssetFinding

	for _, cve := range cves {
		if isVersionAffected(target.Version, cve.DefaultStatus, cve.Versions) {
			score, severity := extractCvssFromRaw(cve.RawJson)
			findings = append(findings, models.AffectedAssetFinding{
				AssetID:    target.AssetID,
				CveID:      cve.CveID,
				Product:    target.Product,
				Version:    target.Version,
				CvssScore:  score,
				Severity:   severity,
				OwnerEmail: target.OwnerEmail,
				Hostname:   target.Hostname,
				IPAddress:  target.IPAddress,
			})
		}
	}

	return findings
}

// extractCvssFromRaw extracts CVSS v3.1 base score and severity from raw_json bytes.
// Called by matchTargetAgainstCves when a target is determined to be affected.
func extractCvssFromRaw(rawJson []byte) (float64, string) {
	var doc struct {
		Metrics struct {
			CvssMetricV31 []struct {
				CvssData struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
		} `json:"metrics"`
	}
	if err := json.Unmarshal(rawJson, &doc); err != nil {
		return 0.0, "UNKNOWN"
	}
	if len(doc.Metrics.CvssMetricV31) > 0 {
		d := doc.Metrics.CvssMetricV31[0].CvssData
		return d.BaseScore, d.BaseSeverity
	}
	return 0.0, "UNKNOWN"
}
