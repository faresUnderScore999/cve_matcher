package matcher

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"nvd-engine/pkd/db"
	"nvd-engine/pkd/models"
)

func MatchTargetAgainstNvd(ctx context.Context, dbs *db.Databases, target models.TargetItem) ([]models.AffectedAssetFinding, error) {
	// Search raw_json for vendor/product matching inside configurations
	query := `
		SELECT cve_id, raw_json 
		FROM cve_records 
		WHERE raw_json->'configurations' IS NOT NULL 
		  AND raw_json::text ILIKE $1 
		  AND raw_json::text ILIKE $2;
	`

	vendorPattern := "%" + target.Vendor + "%"
	productPattern := "%" + target.Product + "%"

	rows, err := dbs.NvdDB.Query(ctx, query, vendorPattern, productPattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.AffectedAssetFinding

	for rows.Next() {
		var cveID string
		var rawJsonBytes []byte

		if err := rows.Scan(&cveID, &rawJsonBytes); err != nil {
			continue
		}

		var payload models.NvdRawJson
		if err := json.Unmarshal(rawJsonBytes, &payload); err != nil {
			continue
		}

		// Version Comparison Logic
		if isAffected(target.Version, payload.Configurations) {
			score, severity := extractCvss(payload.Metrics)
			findings = append(findings, models.AffectedAssetFinding{
				AssetID:   target.AssetID,
				CveID:     cveID,
				CvssScore: score,
				Severity:  severity,
			})
		}
	}

	return findings, nil
}

func extractCvss(metrics models.NvdMetrics) (float64, string) {
	if len(metrics.CvssMetricV31) > 0 {
		data := metrics.CvssMetricV31[0].CvssData
		return data.BaseScore, data.BaseSeverity
	}
	return 0.0, "UNKNOWN"
}

func isAffected(assetVersion string, configs []models.NvdConfigNode) bool {
	for _, config := range configs {
		for _, node := range config.Nodes {
			for _, match := range node.CpeMatch {
				if IsVersionAffected(assetVersion, match) {
					return true
				}
			}
		}
	}
	return false
}

// IsVersionAffected checks if the given asset version falls within the vulnerable range
// defined by the CPE match criteria.
func IsVersionAffected(assetVersion string, match models.CpeMatch) bool {
	if !match.Vulnerable {
		return false
	}

	if assetVersion == "" {
		// If no version specified, consider it affected only if there's no version constraints
		return match.VersionStartIncluding == "" &&
			match.VersionStartExcluding == "" &&
			match.VersionEndIncluding == "" &&
			match.VersionEndExcluding == ""
	}

	// Check version start constraints
	if match.VersionStartIncluding != "" {
		cmp := compareVersions(assetVersion, match.VersionStartIncluding)
		if cmp == models.VersionInvalid || cmp == models.VersionLess {
			return false
		}
	}

	if match.VersionStartExcluding != "" {
		cmp := compareVersions(assetVersion, match.VersionStartExcluding)
		if cmp == models.VersionInvalid || cmp == models.VersionLess || cmp == models.VersionEqual {
			return false
		}
	}

	// Check version end constraints
	if match.VersionEndIncluding != "" {
		cmp := compareVersions(assetVersion, match.VersionEndIncluding)
		if cmp == models.VersionInvalid || cmp == models.VersionGreater {
			return false
		}
	}

	if match.VersionEndExcluding != "" {
		cmp := compareVersions(assetVersion, match.VersionEndExcluding)
		if cmp == models.VersionInvalid || cmp == models.VersionGreater || cmp == models.VersionEqual {
			return false
		}
	}

	return true
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