package matcher

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"nvd-engine/pkd/db"
	"nvd-engine/pkd/models"

	"github.com/google/uuid"
)

// MatchResult holds a target item and its matching CVE findings
type MatchResult struct {
	Target   models.TargetItem
	Findings []models.AffectedAssetFinding
}

func FetchAllTargetItems(ctx context.Context, dbs *db.Databases) ([]models.TargetItem, error) {
	var targets []models.TargetItem

	// 1. Fetch Network Devices
	netTargets, err := fetchNetworkDevices(ctx, dbs)
	if err != nil {
		log.Printf("Error fetching network devices: %v", err)
	} else {
		targets = append(targets, netTargets...)
	}

	// 2. Fetch Server Assets (Installed Software + OS)
	serverTargets, err := fetchServerAssets(ctx, dbs)
	if err != nil {
		log.Printf("Error fetching server assets: %v", err)
	} else {
		targets = append(targets, serverTargets...)
	}

	// 3. Fetch Endpoint Assets (Installed Software + OS)
	endpointTargets, err := fetchEndpointAssets(ctx, dbs)
	if err != nil {
		log.Printf("Error fetching endpoint assets: %v", err)
	} else {
		targets = append(targets, endpointTargets...)
	}

	return targets, nil
}

func fetchNetworkDevices(ctx context.Context, dbs *db.Databases) ([]models.TargetItem, error) {
	query := `
		SELECT a.asset_id, n.vendor, n.model, COALESCE(n.firmware_version, ''), COALESCE(n.firmware_cpe, '')
		FROM assets a
		JOIN network_device_assets n ON a.asset_id = n.asset_id
		WHERE a.status = 'ACTIVE';
	`
	rows, err := dbs.NeonDB.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.TargetItem
	for rows.Next() {
		var id uuid.UUID
		var vendor, model, version, cpe string
		if err := rows.Scan(&id, &vendor, &model, &version, &cpe); err != nil {
			continue
		}
		list = append(list, models.TargetItem{
			AssetID:     id,
			AssetType:   "NETWORK",
			Vendor:      vendor,
			Product:     model,
			Version:     version,
			CpeCriteria: cpe,
		})
	}
	for _, t := range list {
		log.Printf("[DEBUG TARGET] Type: %-10s | Vendor: %-15s | Product: %-20s | Version: %-10s | ID: %s",
			t.AssetType, t.Vendor, t.Product, t.Version, t.AssetID)
	}
	return list, nil
}

func fetchServerAssets(ctx context.Context, dbs *db.Databases) ([]models.TargetItem, error) {
	query := `
		SELECT a.asset_id, 
		       COALESCE(s.os_name, ''), 
		       COALESCE(s.os_version, ''),
		       COALESCE(s.kernel_version, ''),
		       s.installed_software
		FROM assets a
		JOIN server_assets s ON a.asset_id = s.asset_id
		WHERE a.status = 'ACTIVE';
	`
	rows, err := dbs.NeonDB.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.TargetItem
	for rows.Next() {
		var id uuid.UUID
		var osName, osVersion, kernelVersion string
		var rawSoftware []byte

		if err := rows.Scan(&id, &osName, &osVersion, &kernelVersion, &rawSoftware); err != nil {
			continue
		}

		// Add OS-level target items
		osTargets := buildOSTargets(id, "SERVER", osName, osVersion, kernelVersion)
		list = append(list, osTargets...)

		// Add installed software target items
		swTargets := parseSoftwareTargets(id, "server_assets", rawSoftware)
		list = append(list, swTargets...)
	}
	return list, nil
}

func fetchEndpointAssets(ctx context.Context, dbs *db.Databases) ([]models.TargetItem, error) {
	query := `
		SELECT a.asset_id, 
		       COALESCE(e.os_name, ''), 
		       COALESCE(e.os_version, ''),
		       e.installed_software
		FROM assets a
		JOIN endpoint_assets e ON a.asset_id = e.asset_id
		WHERE a.status = 'ACTIVE';
	`
	rows, err := dbs.NeonDB.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.TargetItem
	for rows.Next() {
		var id uuid.UUID
		var osName, osVersion string
		var rawSoftware []byte

		if err := rows.Scan(&id, &osName, &osVersion, &rawSoftware); err != nil {
			continue
		}

		// Add OS-level target items (endpoints don't have kernel_version)
		osTargets := buildOSTargets(id, "ENDPOINT", osName, osVersion, "")
		list = append(list, osTargets...)

		// Add installed software target items
		swTargets := parseSoftwareTargets(id, "endpoint_assets", rawSoftware)
		list = append(list, swTargets...)
	}
	// ==================== TEMP DEBUG START ====================

	return list, nil
}

// buildOSTargets creates TargetItem entries for OS-level CVE matching.
// It maps common OS names to their CPE vendor/product equivalents.
func buildOSTargets(assetID uuid.UUID, assetType, osName, osVersion, kernelVersion string) []models.TargetItem {
	var targets []models.TargetItem

	osName = strings.TrimSpace(osName)
	osVersion = strings.TrimSpace(osVersion)

	if osName == "" {
		return targets
	}

	// Normalize OS name for matching
	osLower := strings.ToLower(osName)

	// Map OS names to CPE vendor/product pairs for NVD matching
	type osMapping struct {
		vendor  string
		product string
	}
	var mappings []osMapping

	switch {
	case strings.Contains(osLower, "windows"):
		mappings = append(mappings, osMapping{vendor: "microsoft", product: "windows"})
		// Try to detect specific Windows version
		if v := detectWindowsProduct(osLower, osVersion); v != "" {
			mappings = append(mappings, osMapping{vendor: "microsoft", product: v})
		}

	case strings.Contains(osLower, "ubuntu"):
		mappings = append(mappings, osMapping{vendor: "canonical", product: "ubuntu_linux"})

	case strings.Contains(osLower, "debian"):
		mappings = append(mappings, osMapping{vendor: "debian", product: "debian_linux"})

	case strings.Contains(osLower, "centos"):
		mappings = append(mappings, osMapping{vendor: "centos", product: "centos"})

	case strings.Contains(osLower, "rhel") || strings.Contains(osLower, "red hat") || strings.Contains(osLower, "redhat"):
		mappings = append(mappings, osMapping{vendor: "redhat", product: "enterprise_linux"})

	case strings.Contains(osLower, "fedora"):
		mappings = append(mappings, osMapping{vendor: "fedoraproject", product: "fedora"})

	case strings.Contains(osLower, "suse") || strings.Contains(osLower, "opensuse"):
		mappings = append(mappings, osMapping{vendor: "suse", product: "linux"})

	case strings.Contains(osLower, "amazon") || strings.Contains(osLower, "aws"):
		mappings = append(mappings, osMapping{vendor: "amazon", product: "amazon_linux"})

	case strings.Contains(osLower, "alpine"):
		mappings = append(mappings, osMapping{vendor: "alpinelinux", product: "alpine_linux"})

	case strings.Contains(osLower, "darwin") || strings.Contains(osLower, "macos") || strings.Contains(osLower, "mac os"):
		mappings = append(mappings, osMapping{vendor: "apple", product: "macos"})

	case strings.Contains(osLower, "linux"):
		// Generic Linux - also add kernel-level matching if kernel version is available
		mappings = append(mappings, osMapping{vendor: "linux", product: "linux_kernel"})
		if kernelVersion != "" {
			targets = append(targets, models.TargetItem{
				AssetID:   assetID,
				AssetType: assetType,
				Vendor:    "linux",
				Product:   "linux_kernel",
				Version:   kernelVersion,
			})
		}
	}

	// Use the most specific version available
	version := osVersion
	if version == "" && kernelVersion != "" {
		version = kernelVersion
	}

	for _, m := range mappings {
		targets = append(targets, models.TargetItem{
			AssetID:   assetID,
			AssetType: assetType,
			Vendor:    m.vendor,
			Product:   m.product,
			Version:   version,
		})
	}

	return targets
}

// detectWindowsProduct attempts to map a Windows version string to its CPE product name
func detectWindowsProduct(osLower, osVersion string) string {
	// Try to detect from version string first
	if osVersion != "" {
		verParts := strings.Split(osVersion, ".")
		if len(verParts) >= 2 {
			major := verParts[0]
			switch major {
			case "10":
				return "windows_10"
			case "11":
				return "windows_11"
			case "6":
				switch verParts[1] {
				case "1":
					return "windows_7"
				case "2":
					return "windows_8"
				case "3":
					return "windows_8_1"
				}
			case "5":
				switch verParts[1] {
				case "2":
					return "windows_server_2003"
				case "1":
					return "windows_xp"
				}
			}
		}
	}

	return "" // broad fallback
}

// parseSoftwareTargets extracts TargetItem entries from installed_software JSONB
func parseSoftwareTargets(assetID uuid.UUID, assetType string, rawSoftware []byte) []models.TargetItem {
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
				AssetID:   assetID,
				AssetType: assetType,
				Vendor:    vendor,
				Product:   name,
				Version:   version,
			})
		}
		return list
	}

	return nil
}
