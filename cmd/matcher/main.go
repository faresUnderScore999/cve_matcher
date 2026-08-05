package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"nvd-engine/pkd/db"
	"nvd-engine/pkd/matcher"
	"nvd-engine/pkd/models"
)

// main is the entry point of the CVE matcher.
//
// It orchestrates the full pipeline:
//  1. Connect to both databases (db package)
//  2. Fetch assets from NeonDB (matcher.FetchAllTargetItems)
//  3. Group targets by (vendor, product) for batched queries
//  4. Match each group against NvdDB CVEs (matcher.MatchBatchTargets)
//  5. Write findings to affected_assets (matcher.InsertFindings)
//     6a. Create tickets for new findings (matcher.CreateTickets)
//     6b. Send email notifications for new tickets (matcher.SendCveEmails)
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting NVD Asset Matcher...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Received shutdown signal, cleaning up...")
		cancel()
	}()

	// Connect to databases
	dbs, err := db.ConnectDatabases(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to databases: %v", err)
	}
	defer dbs.Close()

	log.Println("Connected to both databases successfully")

	// Run the matching process
	if err := runMatching(ctx, dbs); err != nil {
		log.Fatalf("Matching process failed: %v", err)
	}

	log.Println("NVD Asset Matcher completed successfully")
}

// vendorProductKey is a unique key for grouping targets by vendor/product pair.
// Used to batch database queries so we query once per pair instead of once per asset.
type vendorProductKey struct {
	vendor  string
	product string
}

// runMatching executes the core matching pipeline.
//
// Steps:
//  1. Fetch all target assets from NeonDB (matcher.FetchAllTargetItems)
//  2. Group targets by (vendor, product) to batch database queries
//  3. Process each group in parallel (concurrency limited to 5)
//     — each group calls matcher.MatchBatchTargets which:
//     a. Looks up CVEs from NvdDB (cve_lookup.go)
//     b. Matches each target in-memory (matcher.go, version.go)
//  4. Collect all findings from all groups
//  5. Insert findings into affected_assets (matcher.InsertFindings)
//     6a. Create tickets in cve_ticket for new findings (matcher.CreateTickets)
//     6b. Send email notifications for newly created tickets (matcher.SendCveEmails)
func runMatching(ctx context.Context, dbs *db.Databases) error {
	startTime := time.Now()
	log.Println("Starting asset-CVE matching process...")

	// Step 1: Fetch all target items from NeonDB
	log.Println("Fetching target assets from NeonDB...")
	targets, err := matcher.FetchAllTargetItems(ctx, dbs)
	if err != nil {
		return err
	}
	log.Printf("Fetched %d target items for matching", len(targets))

	if len(targets) == 0 {
		log.Println("No target items found, nothing to match")
		return nil
	}

	// Step 2: Group targets by (vendor, product) to batch database queries
	groups := make(map[vendorProductKey][]models.TargetItem)
	for _, t := range targets {
		key := vendorProductKey{vendor: t.Vendor, product: t.Product}
		groups[key] = append(groups[key], t)
	}
	log.Printf("Grouped into %d unique (vendor, product) pairs (vs %d individual assets)", len(groups), len(targets))

	// Step 3: Process each group in parallel
	var (
		allMatches     []matcher.MatchResult
		mu             sync.Mutex
		wg             sync.WaitGroup
		semaphore      = make(chan struct{}, 5) // Limit concurrency to 5
		totalCvesFound int
	)

	// Sort keys for deterministic ordering
	type groupEntry struct {
		key   vendorProductKey
		count int
	}
	var sortedGroups []groupEntry
	for k, v := range groups {
		sortedGroups = append(sortedGroups, groupEntry{key: k, count: len(v)})
	}
	sort.Slice(sortedGroups, func(i, j int) bool {
		if sortedGroups[i].key.vendor != sortedGroups[j].key.vendor {
			return sortedGroups[i].key.vendor < sortedGroups[j].key.vendor
		}
		return sortedGroups[i].key.product < sortedGroups[j].key.product
	})

	groupIndex := 0
	for _, entry := range sortedGroups {
		groupIndex++
		key := entry.key
		batch := groups[key]

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore

		go func(idx int, vendor, product string, batch []models.TargetItem) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore

			log.Printf("[Group %d/%d] Querying CVEs for vendor=%s, product=%s (%d assets in group)",
				idx, len(sortedGroups), vendor, product, len(batch))

			results, err := matcher.MatchBatchTargets(ctx, dbs, vendor, product, batch)
			if err != nil {
				log.Printf("Error matching group vendor=%s, product=%s: %v", vendor, product, err)
				return
			}

			if len(results) > 0 {
				groupFindings := 0
				for _, r := range results {
					groupFindings += len(r.Findings)
				}

				mu.Lock()
				allMatches = append(allMatches, results...)
				totalCvesFound += groupFindings
				mu.Unlock()

				log.Printf("[Group %d/%d] Found %d CVE matches across %d assets for vendor=%s, product=%s",
					idx, len(sortedGroups), groupFindings, len(results), vendor, product)
			} else {
				log.Printf("[Group %d/%d] No matches for vendor=%s, product=%s (%d assets)",
					idx, len(sortedGroups), vendor, product, len(batch))
			}
		}(groupIndex, key.vendor, key.product, batch)
	}

	wg.Wait()

	// Step 4: Collect all findings
	var totalFindings []models.AffectedAssetFinding
	assetsWithFindings := 0
	for _, result := range allMatches {
		totalFindings = append(totalFindings, result.Findings...)
		if len(result.Findings) > 0 {
			assetsWithFindings++
		}
	}

	log.Printf("Total: %d CVE matches across %d assets (%d groups processed)",
		len(totalFindings), assetsWithFindings, len(sortedGroups))

	// Step 5: Insert findings into affected_assets table
	if len(totalFindings) > 0 {
		log.Println("Inserting findings into affected_assets table...")
		if err := matcher.InsertFindings(ctx, dbs, totalFindings); err != nil {
			return err
		}

		// Step 6a: Create tickets for new findings
		log.Println("Creating tickets for new findings...")
		newTickets, err := matcher.CreateTickets(ctx, dbs, totalFindings)
		if err != nil {
			log.Printf("Error creating tickets: %v", err)
			// Non-fatal — findings are already in affected_assets
		}

		// Step 6b: Send email notifications for newly created tickets
		if len(newTickets) > 0 {
			log.Printf("Sending %d email notifications...", len(newTickets))
			matcher.SendCveEmails(newTickets)
		} else {
			log.Println("No new tickets to send notifications for")
		}
	}

	elapsed := time.Since(startTime)
	log.Printf("Matching process completed in %s", elapsed)
	return nil
}
