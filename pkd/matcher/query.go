package matcher

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"

	"nvd-engine/pkd/db"
	"nvd-engine/pkd/models"

	"github.com/jackc/pgx/v5"
)

// CveLookupResult holds all CVE data for a single vendor/product pair query
type CveLookupResult struct {
	CveID         string
	RawJson       []byte
	DefaultStatus string
	Versions      []models.CveVersion
}

// fetchCvesByVendorProduct queries the NVD database once for a vendor/product pair
// and returns all matching CVEs grouped by cve_id.
func fetchCvesByVendorProduct(ctx context.Context, dbs *db.Databases, vendor, product string) ([]CveLookupResult, error) {
	query := `
		SELECT cr.cve_id, cr.raw_json,
		       COALESCE(ca.default_status, ''),
		       COALESCE(cv.version, ''),
		       COALESCE(cv.status, ''),
		       COALESCE(cv.less_than, ''),
		       COALESCE(cv.less_than_or_equal, '')
		FROM cve_records cr
		JOIN cve_affected ca ON ca.cve_id = cr.cve_id
		LEFT JOIN cve_versions cv ON cv.affected_id = ca.id
		WHERE ca.vendor ILIKE $1 AND ca.product ILIKE $2;
	`

	vendorPattern := "%" + vendor + "%"
	productPattern := "%" + product + "%"

	rows, err := dbs.NvdDB.Query(ctx, query, vendorPattern, productPattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groupMap := make(map[string]*CveLookupResult)
	var orderedKeys []string

	for rows.Next() {
		var cveID, defaultStatus, version, status, lessThan, lessThanOrEq string
		var rawJson []byte

		if err := rows.Scan(&cveID, &rawJson, &defaultStatus, &version, &status, &lessThan, &lessThanOrEq); err != nil {
			continue
		}

		grp, exists := groupMap[cveID]
		if !exists {
			grp = &CveLookupResult{
				CveID:         cveID,
				RawJson:       rawJson,
				DefaultStatus: defaultStatus,
			}
			groupMap[cveID] = grp
			orderedKeys = append(orderedKeys, cveID)
		}

		// Only add version entry if at least one version field is non-empty
		if version != "" || lessThan != "" || lessThanOrEq != "" {
			grp.Versions = append(grp.Versions, models.CveVersion{
				Version:         version,
				Status:          status,
				LessThan:        lessThan,
				LessThanOrEqual: lessThanOrEq,
			})
		}
	}

	result := make([]CveLookupResult, 0, len(orderedKeys))
	for _, key := range orderedKeys {
		result = append(result, *groupMap[key])
	}
	return result, nil
}

// matchTargetAgainstCves checks a single target against pre-fetched CVE lookup results.
// No database queries are made — all matching is done in-memory.
func matchTargetAgainstCves(target models.TargetItem, cves []CveLookupResult) []models.AffectedAssetFinding {
	var findings []models.AffectedAssetFinding

	for _, cve := range cves {
		if isVersionAffected(target.Version, cve.DefaultStatus, cve.Versions) {
			score, severity := extractCvssFromRaw(cve.RawJson)
			findings = append(findings, models.AffectedAssetFinding{
				AssetID:   target.AssetID,
				CveID:     cve.CveID,
				CvssScore: score,
				Severity:  severity,
			})
		}
	}

	return findings
}

// MatchTargetAgainstNvd matches a single target against the NVD database.
// For batch processing multiple targets that share the same vendor/product,
// use MatchBatchTargets instead for better performance.
func MatchTargetAgainstNvd(ctx context.Context, dbs *db.Databases, target models.TargetItem) ([]models.AffectedAssetFinding, error) {
	cves, err := fetchCvesByVendorProduct(ctx, dbs, target.Vendor, target.Product)
	if err != nil {
		return nil, err
	}
	return matchTargetAgainstCves(target, cves), nil
}

// MatchBatchTargets matches multiple targets that share the same vendor/product
// against the NVD database using a single query. This is much more efficient
// than calling MatchTargetAgainstNvd for each target individually.
func MatchBatchTargets(ctx context.Context, dbs *db.Databases, vendor, product string, targets []models.TargetItem) ([]MatchResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// Single database query for all targets with this vendor/product
	cves, err := fetchCvesByVendorProduct(ctx, dbs, vendor, product)
	if err != nil {
		return nil, err
	}

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

// extractCvssFromRaw extracts CVSS v3.1 base score and severity from raw_json bytes
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

// isVersionAffected determines if the asset version is affected by a CVE
// based on the version entries and default status.
func isVersionAffected(assetVersion, defaultStatus string, versions []models.CveVersion) bool {
	if len(versions) == 0 {
		// No version constraints: use default_status
		return defaultStatus == "affected"
	}

	// Track explicit matches
	var matchedAffected, matchedUnaffected bool

	for _, v := range versions {
		if isVersionMatch(assetVersion, v) {
			switch v.Status {
			case "affected":
				matchedAffected = true
			case "unaffected":
				matchedUnaffected = true
			}
		}
	}

	// If any unaffected match overrides, the asset is NOT affected
	if matchedUnaffected {
		return false
	}

	// If any affected match found, the asset IS affected
	if matchedAffected {
		return true
	}

	// No version entries matched: fall back to default_status
	return defaultStatus == "affected"
}

// isVersionMatch checks if the asset version matches a single version constraint
func isVersionMatch(assetVersion string, v models.CveVersion) bool {
	if assetVersion == "" {
		// No asset version: only match if there are no constraints
		return v.Version == "" && v.LessThan == "" && v.LessThanOrEqual == ""
	}

	// Exact version match
	if v.Version != "" {
		cmp := compareVersions(assetVersion, v.Version)
		if cmp == models.VersionEqual {
			return true
		}
	}

	// less_than constraint: assetVersion < v.LessThan
	if v.LessThan != "" {
		cmp := compareVersions(assetVersion, v.LessThan)
		if cmp == models.VersionLess {
			return true
		}
	}

	// less_than_or_equal constraint: assetVersion <= v.LessThanOrEqual
	if v.LessThanOrEqual != "" {
		cmp := compareVersions(assetVersion, v.LessThanOrEqual)
		if cmp == models.VersionLess || cmp == models.VersionEqual {
			return true
		}
	}

	return false
}

// compareVersions compares two version strings numerically.
// Returns VersionLess, VersionEqual, VersionGreater, or VersionInvalid.
func compareVersions(v1, v2 string) models.VersionCompareResult {
	// Split into parts
	parts1 := splitVersion(v1)
	parts2 := splitVersion(v2)

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var num1, num2 int64
		var err1, err2 error

		if i < len(parts1) {
			num1, err1 = strconv.ParseInt(parts1[i], 10, 64)
		} else {
			num1 = 0
			err1 = nil
		}

		if i < len(parts2) {
			num2, err2 = strconv.ParseInt(parts2[i], 10, 64)
		} else {
			num2 = 0
			err2 = nil
		}

		// If both parts are numeric, compare numerically
		if err1 == nil && err2 == nil {
			if num1 < num2 {
				return models.VersionLess
			}
			if num1 > num2 {
				return models.VersionGreater
			}
			continue
		}

		// If one or both are non-numeric, compare as strings
		s1 := parts1[i]
		s2 := parts2[i]
		if s1 < s2 {
			return models.VersionLess
		}
		if s1 > s2 {
			return models.VersionGreater
		}
	}

	return models.VersionEqual
}

// splitVersion splits a version string into dot-separated parts, stripping non-numeric prefixes
func splitVersion(v string) []string {
	// Remove common prefixes like "v", "V", "version ", etc.
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	v = strings.TrimPrefix(v, "version ")
	v = strings.TrimPrefix(v, "Version ")

	return strings.Split(v, ".")
}

// InsertFindings inserts matched findings into the affected_assets table in NeonDB
func InsertFindings(ctx context.Context, dbs *db.Databases, findings []models.AffectedAssetFinding) error {
	if len(findings) == 0 {
		log.Println("No findings to insert")
		return nil
	}

	query := `
		INSERT INTO affected_assets (asset_id, cve_id, cvss_score, severity, matched_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (asset_id, cve_id) DO NOTHING;
	`

	batch := &pgx.Batch{}
	for _, f := range findings {
		batch.Queue(query, f.AssetID, f.CveID, f.CvssScore, f.Severity)
	}

	br := dbs.NeonDB.SendBatch(ctx, batch)
	defer br.Close()

	var inserted int
	for range findings {
		_, err := br.Exec()
		if err != nil {
			log.Printf("Error inserting finding: %v", err)
			continue
		}
		inserted++
	}

	log.Printf("Inserted %d/%d findings into affected_assets", inserted, len(findings))
	return nil
}
