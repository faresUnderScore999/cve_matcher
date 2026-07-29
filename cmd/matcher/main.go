package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"nvd-engine/pkd/db"
	"nvd-engine/pkd/matcher"
	"nvd-engine/pkd/models"
)

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

	// Step 2: Match each target against NVD database
	var (
		allFindings []matcher.MatchResult
		mu          sync.Mutex
		wg          sync.WaitGroup
		semaphore   = make(chan struct{}, 5) // Limit concurrency to 5
	)

	for i, target := range targets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore

		go func(idx int, t models.TargetItem) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore

			log.Printf("[%d/%d] Matching asset %s (vendor=%s, product=%s, version=%s)",
				idx+1, len(targets), t.AssetID, t.Vendor, t.Product, t.Version)

			findings, err := matcher.MatchTargetAgainstNvd(ctx, dbs, t)
			if err != nil {
				log.Printf("Error matching asset %s: %v", t.AssetID, err)
				return
			}

			if len(findings) > 0 {
				mu.Lock()
				allFindings = append(allFindings, matcher.MatchResult{
					Target:   t,
					Findings: findings,
				})
				mu.Unlock()
				log.Printf("Found %d CVE matches for asset %s", len(findings), t.AssetID)
			}
		}(i, target)
	}

	wg.Wait()

	// Step 3: Collect all findings and insert into affected_assets
	var totalFindings []models.AffectedAssetFinding
	for _, result := range allFindings {
		totalFindings = append(totalFindings, result.Findings...)
	}

	log.Printf("Total matches found: %d across %d assets", len(totalFindings), len(allFindings))

	// Step 4: Insert findings into affected_assets table
	if len(totalFindings) > 0 {
		log.Println("Inserting findings into affected_assets table...")
		if err := matcher.InsertFindings(ctx, dbs, totalFindings); err != nil {
			return err
		}
	}

	elapsed := time.Since(startTime)
	log.Printf("Matching process completed in %s", elapsed)
	return nil
}