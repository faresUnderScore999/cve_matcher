package matcher

import (
	"context"
	"fmt"
	"log"
	"time"

	"nvd-engine/pkd/db"
	"nvd-engine/pkd/models"

	"github.com/jackc/pgx/v5"
)

// slaDays maps severity levels to the number of days allowed for resolution.
var slaDays = map[string]int{
	"CRITICAL": 7,
	"HIGH":     14,
	"MEDIUM":   30,
	"LOW":      60,
	"UNKNOWN":  30,
}

// priorityMap maps severity levels to ticket priority.
var priorityMap = map[string]string{
	"CRITICAL": "P1",
	"HIGH":     "P2",
	"MEDIUM":   "P3",
	"LOW":      "P4",
	"UNKNOWN":  "P3",
}

// CreateTickets inserts matched CVE findings into the cve_ticket table.
// Only new (asset_id, cve_id) pairs are inserted (ON CONFLICT DO NOTHING).
// Returns the list of newly created tickets for email notification.
//
// Pipeline stage 6a: Called by main.go after InsertFindings.
// Each ticket is assigned:
//   - status = "OPEN"
//   - priority based on severity (CRITICAL→P1, HIGH→P2, MEDIUM→P3, LOW→P4)
//   - due_date = NOW() + SLA days (CRITICAL=7d, HIGH=14d, MEDIUM=30d, LOW=60d)
//   - description = summary of the finding
func CreateTickets(ctx context.Context, dbs *db.Databases, findings []models.AffectedAssetFinding) ([]models.CveTicket, error) {
	if len(findings) == 0 {
		log.Println("No findings to create tickets for")
		return nil, nil
	}

	now := time.Now()

	query := `
		INSERT INTO cve_ticket (asset_id, cve_id, status, priority, description, due_date, created_at, updated_at)
		VALUES ($1, $2, 'OPEN', $3, $4, $5, $6, $6)
		ON CONFLICT (asset_id, cve_id) DO NOTHING
		RETURNING id;
	`

	batch := &pgx.Batch{}
	// Track mapping: batch index -> ticket metadata for returned tickets
	type pendingTicket struct {
		finding  models.AffectedAssetFinding
		priority string
		dueDate  time.Time
		desc     string
	}
	var pending []pendingTicket

	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "UNKNOWN"
		}
		priority := priorityMap[sev]
		if priority == "" {
			priority = "P3"
		}
		days := slaDays[sev]
		if days == 0 {
			days = 30
		}
		dueDate := now.AddDate(0, 0, days)

		desc := fmt.Sprintf(
			"%s affects %s %s on host %s (%s)",
			f.CveID, f.Product, f.Version, f.Hostname, f.IPAddress,
		)

		batch.Queue(query, f.AssetID, f.CveID, priority, desc, dueDate, now)
		pending = append(pending, pendingTicket{
			finding:  f,
			priority: priority,
			dueDate:  dueDate,
			desc:     desc,
		})
	}

	br := dbs.NeonDB.SendBatch(ctx, batch)
	defer br.Close()

	var newTickets []models.CveTicket
	for _, p := range pending {
		var insertedID int64
		row := br.QueryRow()
		if err := row.Scan(&insertedID); err != nil {
			if err == pgx.ErrNoRows {
				// conflict or duplicate; skip silently
				continue
			}
			return nil, err
		}

		newTickets = append(newTickets, models.CveTicket{
			AssetID:     p.finding.AssetID,
			CveID:       p.finding.CveID,
			Status:      "OPEN",
			Priority:    p.priority,
			Description: p.desc,
			DueDate:     p.dueDate,
			CreatedAt:   now,
			OwnerEmail:  p.finding.OwnerEmail,
			Hostname:    p.finding.Hostname,
			IPAddress:   p.finding.IPAddress,
			Product:     p.finding.Product,
			Version:     p.finding.Version,
			CvssScore:   p.finding.CvssScore,
			Severity:    p.finding.Severity,
		})
	}

	log.Printf("Created %d new tickets (%d existing skipped)", len(newTickets), len(pending)-len(newTickets))
	return newTickets, nil
}
