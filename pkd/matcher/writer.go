package matcher

import (
	"context"
	"log"

	"nvd-engine/pkd/db"
	"nvd-engine/pkd/models"

	"github.com/jackc/pgx/v5"
)

// InsertFindings inserts matched findings into the affected_assets table in NeonDB.
//
// Pipeline stage 5: This is the final stage of the pipeline.
// Called by main.go after all matching groups complete.
// Uses a pgx batch for efficient bulk insertion with ON CONFLICT DO NOTHING
// to avoid duplicate (asset_id, cve_id) rows.
func InsertFindings(ctx context.Context, dbs *db.Databases, findings []models.AffectedAssetFinding) error {
	if len(findings) == 0 {
		log.Println("No findings to insert")
		return nil
	}

	query := `
		INSERT INTO affected_assets (asset_id, cve_id, product, cvss_score, severity, matched_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (asset_id, cve_id) DO NOTHING;
	`

	batch := &pgx.Batch{}
	for _, f := range findings {
		batch.Queue(query, f.AssetID, f.CveID, f.Product, f.CvssScore, f.Severity)
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
