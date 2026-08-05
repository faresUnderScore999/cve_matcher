// Package matcher implements the CVE matching pipeline.
//
// The pipeline stages are:
//  1. Fetch assets from NeonDB (fetcher.go)
//  2. Transform assets into TargetItems (os_mapping.go, software_parser.go)
//  3. Lookup CVEs from NvdDB (cve_lookup.go)
//  4. Match targets against CVEs in-memory (matcher.go, version.go)
//  5. Write findings to affected_assets (writer.go)
package matcher

import (
	"context"
	"regexp"
	"strings"

	"nvd-engine/pkd/db"
	"nvd-engine/pkd/models"
)

// CveLookupResult holds all CVE data for a single vendor/product pair query.
// It is produced by the lookup stage and consumed by the matching stage.
type CveLookupResult struct {
	CveID         string
	RawJson       []byte
	DefaultStatus string
	Versions      []models.CveVersion
}

// fetchCvesByVendorProduct queries the NVD database once for a vendor/product pair
// and returns all matching CVEs grouped by cve_id.
//
// It queries the cve_affected/cve_versions tables (the primary source).
// Called by MatchBatchTargets as the first lookup source.
func fetchCvesByVendorProduct(ctx context.Context, dbs *db.Databases, vendor, product string) ([]CveLookupResult, error) {
	// 1. SQL Query using REGEXP_REPLACE and LOWER to ignore spaces, punctuation, and casing.
	// regexp_replace(str, '[^a-zA-Z0-9]', '', 'g') removes all non-alphanumeric characters.
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
		WHERE ($1 = '' OR LOWER(REGEXP_REPLACE(ca.vendor, '[^a-zA-Z0-9]', '', 'g')) LIKE $2) 
		  AND LOWER(REGEXP_REPLACE(ca.product, '[^a-zA-Z0-9]', '', 'g')) LIKE $3;
	`

	// 2. Helper function to sanitize Go input strings identically
	sanitize := func(s string) string {
		reg := regexp.MustCompile(`[^a-zA-Z0-9]+`)
		return strings.ToLower(reg.ReplaceAllString(s, ""))
	}

	cleanVendor := sanitize(vendor)
	cleanProduct := sanitize(product)

	vendorPattern := ""
	if cleanVendor != "" {
		vendorPattern = "%" + cleanVendor + "%"
	}
	productPattern := "%" + cleanProduct + "%"

	// 3. Execute query with cleaned input parameters
	rows, err := dbs.NvdDB.Query(ctx, query, cleanVendor, vendorPattern, productPattern)
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

// fetchCvesByCpeTable queries the cve_cpes table joined with cve_records to find
// CVEs that match a vendor/product via CPE strings. This is a fallback/merge source
// for CVEs that may not be captured by the cve_affected/cve_versions tables.
//
// Called by MatchBatchTargets as the second lookup source, then merged with
// the results of fetchCvesByVendorProduct via mergeCveResults.
func fetchCvesByCpeTable(ctx context.Context, dbs *db.Databases, vendor, product string) ([]CveLookupResult, error) {
	// Query cve_cpes joined with cve_records to get the raw_json metrics
	query := `
		SELECT cr.cve_id, cr.raw_json, cc.cpe,
		       COALESCE(cc.version_start_including, ''),
		       COALESCE(cc.version_end_excluding, ''),
		       COALESCE(cc.version_start_excluding, ''),
		       COALESCE(cc.version_end_including, '')
		FROM cve_cpes cc
		JOIN cve_records cr ON cr.cve_id = cc.cve_id
		WHERE cc.vulnerable = true
		  AND ($1 = '' OR LOWER(REGEXP_REPLACE(split_part(cc.cpe, ':', 4), '[^a-zA-Z0-9]', '', 'g')) LIKE $2)
		  AND LOWER(REGEXP_REPLACE(split_part(cc.cpe, ':', 5), '[^a-zA-Z0-9]', '', 'g')) LIKE $3;
	`

	// Helper to sanitize vendor/product strings
	sanitize := func(s string) string {
		reg := regexp.MustCompile(`[^a-zA-Z0-9]+`)
		return strings.ToLower(reg.ReplaceAllString(s, ""))
	}

	cleanVendor := sanitize(vendor)
	cleanProduct := sanitize(product)

	vendorPattern := ""
	if cleanVendor != "" {
		vendorPattern = "%" + cleanVendor + "%"
	}
	productPattern := "%" + cleanProduct + "%"

	rows, err := dbs.NvdDB.Query(ctx, query, cleanVendor, vendorPattern, productPattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	groupMap := make(map[string]*CveLookupResult)
	var orderedKeys []string

	for rows.Next() {
		var cveID, cpe, vStartInc, vEndExc, vStartExc, vEndInc string
		var rawJson []byte

		if err := rows.Scan(&cveID, &rawJson, &cpe, &vStartInc, &vEndExc, &vStartExc, &vEndInc); err != nil {
			continue
		}

		grp, exists := groupMap[cveID]
		if !exists {
			grp = &CveLookupResult{
				CveID:         cveID,
				RawJson:       rawJson,
				DefaultStatus: "unaffected", // Fallback default status for cve_cpes
			}
			groupMap[cveID] = grp
			orderedKeys = append(orderedKeys, cveID)
		}

		// Map range bounds into CveVersion records
		if vStartInc != "" || vEndExc != "" || vStartExc != "" || vEndInc != "" {
			// Version boundary: >= vStartInc
			if vStartInc != "" {
				grp.Versions = append(grp.Versions, models.CveVersion{
					GreaterThanOrEqual: vStartInc,
					Status:             "affected",
				})
			}
			// Boundary: > vStartExc
			if vStartExc != "" {
				grp.Versions = append(grp.Versions, models.CveVersion{
					GreaterThan: vStartExc,
					Status:      "affected",
				})
			}
			// Boundary: < vEndExc
			if vEndExc != "" {
				grp.Versions = append(grp.Versions, models.CveVersion{
					LessThan: vEndExc,
					Status:   "affected",
				})
			}
			// Boundary: <= vEndInc
			if vEndInc != "" {
				grp.Versions = append(grp.Versions, models.CveVersion{
					LessThanOrEqual: vEndInc,
					Status:          "affected",
				})
			}
		} else {
			// If no explicit ranges, check if version is embedded inside CPE field 6
			// e.g., cpe:2.3:a:meddream:pacs_server:7.3.6.870:*:*:*
			cpeParts := strings.Split(cpe, ":")
			if len(cpeParts) >= 6 && cpeParts[5] != "*" && cpeParts[5] != "-" {
				grp.Versions = append(grp.Versions, models.CveVersion{
					Version: cpeParts[5],
					Status:  "affected",
				})
			}
		}
	}

	result := make([]CveLookupResult, 0, len(orderedKeys))
	for _, key := range orderedKeys {
		result = append(result, *groupMap[key])
	}
	return result, nil
}

// mergeCveResults merges two CVE lookup result slices, deduplicating by cve_id.
// The first occurrence's RawJson and DefaultStatus are kept; Versions are appended
// from both sources (deduplicated by their string representation).
//
// Called by MatchBatchTargets to combine results from fetchCvesByVendorProduct
// and fetchCvesByCpeTable.
func mergeCveResults(a, b []CveLookupResult) []CveLookupResult {
	merged := make([]CveLookupResult, 0, len(a)+len(b))
	seen := make(map[string]int) // cve_id -> index in merged

	for _, cve := range a {
		merged = append(merged, cve)
		seen[cve.CveID] = len(merged) - 1
	}

	for _, cve := range b {
		if idx, exists := seen[cve.CveID]; exists {
			// Merge versions, avoiding duplicates
			existing := &merged[idx]
			existingVersions := make(map[string]bool)
			for _, v := range existing.Versions {
				existingVersions[versionKey(v)] = true
			}
			for _, v := range cve.Versions {
				if !existingVersions[versionKey(v)] {
					existing.Versions = append(existing.Versions, v)
				}
			}
		} else {
			merged = append(merged, cve)
			seen[cve.CveID] = len(merged) - 1
		}
	}

	return merged
}

// versionKey returns a unique string key for a CveVersion for deduplication.
// Used by mergeCveResults to avoid duplicate version entries.
func versionKey(v models.CveVersion) string {
	return v.Version + "|" + v.Status + "|" + v.LessThan + "|" + v.LessThanOrEqual + "|" + v.GreaterThan + "|" + v.GreaterThanOrEqual
}
