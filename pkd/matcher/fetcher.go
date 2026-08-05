package matcher

import (
	"context"
	"log"

	"nvd-engine/pkd/db"
	"nvd-engine/pkd/models"

	"github.com/google/uuid"
)

// FetchAllTargetItems fetches all active assets from NeonDB and converts them
// into TargetItems for CVE matching.
//
// Pipeline stage 1: This is the entry point of the fetch stage.
// Called by main.go at the start of the matching process.
//
// It aggregates targets from three asset types:
//  1. Network devices (fetchNetworkDevices)
//  2. Server assets — OS + installed software (fetchServerAssets)
//  3. Endpoint assets — OS + installed software (fetchEndpointAssets)
//
// Errors fetching one asset type are logged but do not abort the whole fetch;
// the other asset types are still processed.
//
// OwnerEmail, Hostname, and IPAddress are fetched from the assets table and
// carried through the pipeline for ticket creation and email notifications.
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

// fetchNetworkDevices queries the network_device_assets table for active
// network devices and converts each row into a TargetItem.
//
// Pipeline stage 1: Called by FetchAllTargetItems.
// Maps: vendor → Vendor, model → Product, firmware_version → Version,
// firmware_cpe → CpeCriteria. Also carries asset metadata (owner_email,
// hostname, ip_address) for ticket/notification stages.
func fetchNetworkDevices(ctx context.Context, dbs *db.Databases) ([]models.TargetItem, error) {
	query := `
		SELECT a.asset_id, n.vendor, n.model, COALESCE(n.firmware_version, ''), COALESCE(n.firmware_cpe, ''),
		       COALESCE(a.owner_email, ''), COALESCE(a.hostname, ''), COALESCE(a.ip_address, '')
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
		var vendor, model, version, cpe, ownerEmail, hostname, ipAddress string
		if err := rows.Scan(&id, &vendor, &model, &version, &cpe, &ownerEmail, &hostname, &ipAddress); err != nil {
			continue
		}
		list = append(list, models.TargetItem{
			AssetID:     id,
			AssetType:   "NETWORK",
			Vendor:      vendor,
			Product:     model,
			Version:     version,
			CpeCriteria: cpe,
			OwnerEmail:  ownerEmail,
			Hostname:    hostname,
			IPAddress:   ipAddress,
		})
	}
	for _, t := range list {
		log.Printf("[DEBUG TARGET] Type: %-10s | Vendor: %-15s | Product: %-20s | Version: %-10s | ID: %s",
			t.AssetType, t.Vendor, t.Product, t.Version, t.AssetID)
	}
	return list, nil
}

// fetchServerAssets queries the server_assets table for active servers.
//
// Pipeline stage 1: Called by FetchAllTargetItems.
// Each server produces two kinds of TargetItems:
//   - OS-level targets via buildOSTargets (os_mapping.go)
//   - Installed software targets via parseSoftwareTargets (software_parser.go)
func fetchServerAssets(ctx context.Context, dbs *db.Databases) ([]models.TargetItem, error) {
	query := `
		SELECT a.asset_id, 
		       COALESCE(s.os_name, ''), 
		       COALESCE(s.os_version, ''),
		       COALESCE(s.kernel_version, ''),
		       s.installed_software,
		       COALESCE(a.owner_email, ''), COALESCE(a.hostname, ''), COALESCE(a.ip_address, '')
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
		var osName, osVersion, kernelVersion, ownerEmail, hostname, ipAddress string
		var rawSoftware []byte

		if err := rows.Scan(&id, &osName, &osVersion, &kernelVersion, &rawSoftware, &ownerEmail, &hostname, &ipAddress); err != nil {
			continue
		}

		// Add OS-level target items
		osTargets := buildOSTargets(id, "SERVER", osName, osVersion, kernelVersion, ownerEmail, hostname, ipAddress)
		list = append(list, osTargets...)

		// Add installed software target items
		swTargets := parseSoftwareTargets(id, "server_assets", rawSoftware, ownerEmail, hostname, ipAddress)
		list = append(list, swTargets...)
	}
	return list, nil
}

// fetchEndpointAssets queries the endpoint_assets table for active endpoints.
//
// Pipeline stage 1: Called by FetchAllTargetItems.
// Each endpoint produces two kinds of TargetItems:
//   - OS-level targets via buildOSTargets (os_mapping.go) — endpoints have no kernel_version
//   - Installed software targets via parseSoftwareTargets (software_parser.go)
func fetchEndpointAssets(ctx context.Context, dbs *db.Databases) ([]models.TargetItem, error) {
	query := `
		SELECT a.asset_id, 
		       COALESCE(e.os_name, ''), 
		       COALESCE(e.os_version, ''),
		       e.installed_software,
		       COALESCE(a.owner_email, ''), COALESCE(a.hostname, ''), COALESCE(a.ip_address, '')
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
		var osName, osVersion, ownerEmail, hostname, ipAddress string
		var rawSoftware []byte

		if err := rows.Scan(&id, &osName, &osVersion, &rawSoftware, &ownerEmail, &hostname, &ipAddress); err != nil {
			continue
		}

		// Add OS-level target items (endpoints don't have kernel_version)
		osTargets := buildOSTargets(id, "ENDPOINT", osName, osVersion, "", ownerEmail, hostname, ipAddress)
		list = append(list, osTargets...)

		// Add installed software target items
		swTargets := parseSoftwareTargets(id, "endpoint_assets", rawSoftware, ownerEmail, hostname, ipAddress)
		list = append(list, swTargets...)
	}

	return list, nil
}
