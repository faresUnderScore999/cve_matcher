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

type Databases struct {
	NeonDB *pgxpool.Pool
	NvdDB  *pgxpool.Pool
}

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

	return &Databases{
		NeonDB: neonPool,
		NvdDB:  nvdPool,
	}, nil
}

func (dbs *Databases) Close() {
	if dbs.NeonDB != nil {
		dbs.NeonDB.Close()
	}
	if dbs.NvdDB != nil {
		dbs.NvdDB.Close()
	}
}