package matcher

import (
	"strconv"
	"strings"

	"nvd-engine/pkd/models"
)

// isVersionAffected determines whether an asset version is affected by a CVE,
// based on the version entries and default status.
//
// Pipeline stage 4b: Called by matchTargetAgainstCves (matcher.go) for each
// CVE found for a target. Uses isVersionMatch for individual constraint checks.
//
// Logic:
//  1. If no version constraints exist, use default_status.
//  2. Track explicit affected/unaffected matches.
//  3. An unaffected match overrides (asset NOT affected).
//  4. An affected match means the asset IS affected.
//  5. If nothing matched, fall back to default_status.
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

// isVersionMatch checks if the asset version matches a single version constraint.
//
// Pipeline stage 4b: Called by isVersionAffected for each CveVersion entry.
// Uses compareVersions for numeric comparison.
func isVersionMatch(assetVersion string, v models.CveVersion) bool {
	if assetVersion == "" {
		// No asset version: only match if there are no constraints
		return v.Version == "" && v.LessThan == "" && v.LessThanOrEqual == "" &&
			v.GreaterThan == "" && v.GreaterThanOrEqual == ""
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

	// greater_than constraint: assetVersion > v.GreaterThan
	if v.GreaterThan != "" {
		cmp := compareVersions(assetVersion, v.GreaterThan)
		if cmp == models.VersionGreater {
			return true
		}
	}

	// greater_than_or_equal constraint: assetVersion >= v.GreaterThanOrEqual
	if v.GreaterThanOrEqual != "" {
		cmp := compareVersions(assetVersion, v.GreaterThanOrEqual)
		if cmp == models.VersionGreater || cmp == models.VersionEqual {
			return true
		}
	}

	return false
}

// compareVersions compares two version strings numerically.
// Returns VersionLess, VersionEqual, VersionGreater, or VersionInvalid.
//
// Pipeline stage 4b: Called by isVersionMatch. Splits versions into
// dot-separated parts via splitVersion and compares part-by-part.
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

// splitVersion splits a version string into dot-separated parts, stripping non-numeric prefixes.
//
// Pipeline stage 4b: Called by compareVersions to normalize version strings
// before numeric comparison.
func splitVersion(v string) []string {
	// Remove common prefixes like "v", "V", "version ", etc.
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	v = strings.TrimPrefix(v, "version ")
	v = strings.TrimPrefix(v, "Version ")

	return strings.Split(v, ".")
}
