// Package db manages database connections for the CVE matcher.
//
// The matcher uses two databases:
//   - NeonDB: remote asset inventory (assets, server_assets, endpoint_assets,
//     network_device_assets, affected_assets)
//   - NvdDB: local CVE database (cve_records, cve_affected, cve_versions, cve_cpes)
//
// Databases is the central handle passed through the pipeline stages
// (fetch → lookup → write) so each stage can query the appropriate database.
package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

// Databases holds the connection pools for both databases used by the matcher.
// It is created by ConnectDatabases and passed to all pipeline stages.
type Databases struct {
	NeonDB *pgxpool.Pool
	NvdDB  *pgxpool.Pool
}

// ConnectDatabases loads environment variables, connects to both databases,
// and verifies the connections with a ping.
//
// Called by main.go at startup.
// Connection settings:
//   - NeonDB: max 10 conns, min 2 conns
//   - NvdDB: max 5 conns, min 1 conn
//
// Returns an error if either URL is missing or a connection/ping fails.
func ConnectDatabases(ctx context.Context) (*Databases, error) {
	// Load .env file if it exists (ignore error if not found)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables or defaults")
	}

	neonURL := os.Getenv("NEON_DATABASE_URL")
	if neonURL == "" {
		return nil, fmt.Errorf("NEON_DATABASE_URL is not set. Set it in .env file or as environment variable")
	}

	nvdURL := os.Getenv("NVD_DATABASE_URL")
	if nvdURL == "" {
		return nil, fmt.Errorf("NVD_DATABASE_URL is not set. Set it in .env file or as environment variable")
	}

	neonConfig, err := pgxpool.ParseConfig(neonURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse neon db url: %w", err)
	}
	neonConfig.MaxConns = 10
	neonConfig.MinConns = 2
	neonConfig.MaxConnLifetime = 30 * time.Minute
	neonConfig.MaxConnIdleTime = 5 * time.Minute

	nvdConfig, err := pgxpool.ParseConfig(nvdURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nvd db url: %w", err)
	}
	nvdConfig.MaxConns = 5
	nvdConfig.MinConns = 1
	nvdConfig.MaxConnLifetime = 30 * time.Minute
	nvdConfig.MaxConnIdleTime = 5 * time.Minute

	neonPool, err := pgxpool.NewWithConfig(ctx, neonConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to neon db: %w", err)
	}

	nvdPool, err := pgxpool.NewWithConfig(ctx, nvdConfig)
	if err != nil {
		neonPool.Close()
		return nil, fmt.Errorf("failed to connect to nvd db: %w", err)
	}

	// Test connections
	if err := neonPool.Ping(ctx); err != nil {
		neonPool.Close()
		nvdPool.Close()
		return nil, fmt.Errorf("failed to ping neon db: %w", err)
	}
	log.Println("Connected to NeonDB successfully")

	if err := nvdPool.Ping(ctx); err != nil {
		neonPool.Close()
		nvdPool.Close()
		return nil, fmt.Errorf("failed to ping nvd db: %w", err)
	}
	log.Println("Connected to NvdDB successfully")

	if err := ensureNeonOutputTables(ctx, neonPool); err != nil {
		neonPool.Close()
		nvdPool.Close()
		return nil, fmt.Errorf("failed to ensure neon output tables: %w", err)
	}

	return &Databases{
		NeonDB: neonPool,
		NvdDB:  nvdPool,
	}, nil
}

func ensureNeonOutputTables(ctx context.Context, pool *pgxpool.Pool) error {
	queries := []string{
		`
		CREATE TABLE IF NOT EXISTS affected_assets (
		    id SERIAL PRIMARY KEY,
		    asset_id UUID NOT NULL,
		    cve_id VARCHAR(50) NOT NULL,
		    product TEXT,
		    cvss_score DOUBLE PRECISION,
		    severity VARCHAR(20),
		    matched_at TIMESTAMP DEFAULT NOW(),
		    UNIQUE(asset_id, cve_id)
		);
		`,
		`
		CREATE TABLE IF NOT EXISTS cve_ticket (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		    asset_id UUID NOT NULL,
		    cve_id VARCHAR(20) NOT NULL,
		    status VARCHAR(20) NOT NULL,
		    priority VARCHAR(10),
		    assigned_to VARCHAR(100),
		    description TEXT,
		    due_date TIMESTAMP,
		    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
		    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
		    resolved_at TIMESTAMP,
		    closed_at TIMESTAMP,
		    UNIQUE(asset_id, cve_id)
		);
		`,
	}

	for _, q := range queries {
		if _, err := pool.Exec(ctx, q); err != nil {
			return err
		}
	}

	log.Println("Ensured NeonDB output tables exist")
	return nil
}

// Close gracefully closes both database connection pools.
// Called by main() via defer after ConnectDatabases succeeds.
func (dbs *Databases) Close() {
	if dbs.NeonDB != nil {
		dbs.NeonDB.Close()
	}
	if dbs.NvdDB != nil {
		dbs.NvdDB.Close()
	}
}
