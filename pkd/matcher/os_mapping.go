package matcher

import (
	"strings"

	"nvd-engine/pkd/models"

	"github.com/google/uuid"
)

// buildOSTargets creates TargetItem entries for OS-level CVE matching.
// It maps common OS names to their CPE vendor/product equivalents.
//
// Pipeline stage 2a: Called by fetchServerAssets and fetchEndpointAssets
// (fetcher.go) to transform raw OS fields into matchable TargetItems.
//
// The mapping is a best-effort heuristic: it normalizes the OS name and
// matches it against known CPE vendor/product pairs (e.g. "Ubuntu" →
// canonical/ubuntu_linux). For generic Linux, it also adds a kernel-level
// target when a kernel version is available.
//
// ownerEmail, hostname, and ipAddress are carried through to the resulting
// TargetItems for the ticket and email notification stages.
func buildOSTargets(assetID uuid.UUID, assetType, osName, osVersion, kernelVersion, ownerEmail, hostname, ipAddress string) []models.TargetItem {
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
				AssetID:    assetID,
				AssetType:  assetType,
				Vendor:     "linux",
				Product:    "linux_kernel",
				Version:    kernelVersion,
				OwnerEmail: ownerEmail,
				Hostname:   hostname,
				IPAddress:  ipAddress,
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
			AssetID:    assetID,
			AssetType:  assetType,
			Vendor:     m.vendor,
			Product:    m.product,
			Version:    version,
			OwnerEmail: ownerEmail,
			Hostname:   hostname,
			IPAddress:  ipAddress,
		})
	}

	return targets
}

// detectWindowsProduct attempts to map a Windows version string to its CPE product name.
//
// Pipeline stage 2a: Called by buildOSTargets when the OS name contains "windows".
// Uses the version string (e.g. "10.0.19045") to determine the specific
// Windows product (e.g. "windows_10"). Returns "" for unknown versions,
// in which case the broad "windows" mapping is used as fallback.
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
