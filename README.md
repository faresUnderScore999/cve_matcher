# CVE Matcher

A Go-based tool that matches assets (network devices, servers, endpoints) against CVE records from a local NVD database to identify vulnerable software versions.

## Architecture

The tool connects to two databases:

- **NeonDB** (remote) — Contains asset inventory: `assets`, `server_assets`, `endpoint_assets`, `network_device_assets`, and the output table `affected_assets`.
- **NvdDB** (local) — Contains CVE data from the [NVD JSON data feeds](https://github.com/fkie-cad/nvd-json-data-feeds) in a normalized schema: `cve_records`, `cve_affected`, `cve_versions`.

## Prerequisites

- Go 1.21+
- PostgreSQL 15+ (for NvdDB)
- Access to a NeonDB instance (or any PostgreSQL for the asset database)

## Database Setup

### NvdDB (Local CVE Database)

The NvdDB uses a normalized schema with three tables:

```sql
-- Core CVE records with raw JSON payload
CREATE TABLE cve_records (
    cve_id   VARCHAR(50) PRIMARY KEY,
    raw_json JSONB
);

-- Affected products (indexed for fast lookups)
CREATE TABLE cve_affected (
    id             SERIAL PRIMARY KEY,
    cve_id         VARCHAR(50) REFERENCES cve_records(cve_id) ON DELETE CASCADE,
    vendor         TEXT,
    product        TEXT,
    default_status VARCHAR(50)
);
CREATE INDEX idx_cve_affected_vendor ON cve_affected(vendor);
CREATE INDEX idx_cve_affected_product ON cve_affected(product);

-- Version constraints for each affected product
CREATE TABLE cve_versions (
    id                SERIAL PRIMARY KEY,
    affected_id       INTEGER REFERENCES cve_affected(id) ON DELETE CASCADE,
    version           VARCHAR(50),
    status            VARCHAR(50),
    less_than         VARCHAR(50),
    less_than_or_equal VARCHAR(50),
    version_type      VARCHAR(50)
);
CREATE INDEX idx_cve_versions_version ON cve_versions(version);
```

### NeonDB (Asset Database)

Expected tables (your schema may vary):

- `assets` — Core asset table with `asset_id` (UUID) and `status`
- `network_device_assets` — Network devices with `vendor`, `model`, `firmware_version`
- `server_assets` — Servers with `os_name`, `os_version`, `kernel_version`, `installed_software` (JSONB)
- `endpoint_assets` — Endpoints with `os_name`, `os_version`, `installed_software` (JSONB)
- `affected_assets` — Output table for matched CVEs

The `affected_assets` table should have:
```sql
CREATE TABLE affected_assets (
    id         SERIAL PRIMARY KEY,
    asset_id   UUID NOT NULL,
    cve_id     VARCHAR(50) NOT NULL,
    cvss_score DOUBLE PRECISION,
    severity   VARCHAR(20),
    matched_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(asset_id, cve_id)
);
```

## Configuration

Create a `.env` file in the project root:

```env
# NeonDB (Remote - Asset Database)
NEON_DATABASE_URL=postgres://user:password@host:port/dbname?sslmode=require

# NvdDB (Local - CVE Database)
NVD_DATABASE_URL=postgres://user:password@localhost:5432/nvd_db?sslmode=disable
```

## Build

### Local build

```bash
go build -o cve-matcher ./cmd/matcher/
```

### Docker build

```bash
docker build -t cve-matcher .
```

## Run

### Local run

```bash
./cve-matcher
```

### Docker run (one-shot)

```bash
docker run --rm \
  -v /path/to/your/.env:/app/.env \
  cve-matcher
```

### Docker run (scheduled — daily at 5:00 AM)

The container is configured to run `crond` in the foreground and execute the matcher every day at 5:00 AM automatically:

```bash
# Run in background (detached)
docker run -d \
  --name cve-matcher \
  -v /path/to/your/.env:/app/.env \
  cve-matcher

# View logs
docker logs -f cve-matcher

# Or pass env vars directly (no .env file needed)
docker run -d \
  --name cve-matcher \
  -e NEON_DATABASE_URL="postgres://user:pass@host:5432/db?sslmode=require" \
  -e NVD_DATABASE_URL="postgres://user:pass@localhost:5432/nvd_db?sslmode=disable" \
  cve-matcher
```

The tool will:
1. Connect to both databases
2. Fetch all active assets from NeonDB (network devices, servers, endpoints)
3. For each asset, query the NvdDB using indexed `vendor`/`product` lookups
4. Evaluate version constraints from `cve_versions` to determine if the asset is affected
5. Insert matched findings into `affected_assets`

## How the Matching Works

### Query Path

Instead of scanning `raw_json::text` with `ILIKE` (slow, no index usage), the matcher uses a JOIN-based query:

```sql
SELECT cr.cve_id, cr.raw_json, ca.default_status, cv.*
FROM cve_records cr
JOIN cve_affected ca ON ca.cve_id = cr.cve_id
LEFT JOIN cve_versions cv ON cv.affected_id = ca.id
WHERE ca.vendor ILIKE $1 AND ca.product ILIKE $2;
```

This leverages **pg_trgm GIN indexes** on `cve_affected.vendor` and `cve_affected.product` for fast `ILIKE '%pattern%'` lookups:

```sql
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX idx_cve_affected_vendor_trgm ON cve_affected USING gin (vendor gin_trgm_ops);
CREATE INDEX idx_cve_affected_product_trgm ON cve_affected USING gin (product gin_trgm_ops);
```

### Batch Processing (Performance Optimization)

Instead of querying the database once per asset (30k queries for 30k assets), the matcher **groups assets by unique (vendor, product) pairs** and queries once per pair:

```
30,000 assets → ~50-200 unique (vendor, product) pairs → 50-200 SQL queries
```

This is handled by `MatchBatchTargets()` in `query.go`:
1. All targets are grouped by `(vendor, product)` in `main.go`
2. For each unique pair, a single SQL query fetches all matching CVEs
3. Each asset in the group is then matched in-memory against the cached results (no additional DB round-trips)

### Version Matching Logic

For each CVE + product combination, the matcher:

1. Iterates over all version entries in `cve_versions`
2. Checks if the asset version matches any constraint:
   - **Exact version**: `version = X`
   - **Less than**: `asset < less_than`
   - **Less than or equal**: `asset <= less_than_or_equal`
3. If a match is found with `status = 'unaffected'`, the asset is **not** vulnerable (override)
4. If a match is found with `status = 'affected'`, the asset **is** vulnerable
5. If no entries match, falls back to `default_status` from `cve_affected`
6. If affected, extracts the CVSS v3.1 score from `raw_json` for severity ranking

### Performance Estimates (30k assets × 250k CVEs)

| Optimization | Estimated Time |
|-------------|---------------|
| Without pg_trgm indexes | 30-60+ minutes (sequential scans) |
| With pg_trgm indexes only | 5-10 minutes |
| **With pg_trgm + batching (current)** | **30-90 seconds** |

## Project Structure

```
├── cmd/matcher/main.go       # Entry point, orchestration
├── pkd/
│   ├── db/database.go        # Database connection management
│   ├── matcher/
│   │   ├── fetcher.go        # Fetches assets from NeonDB
│   │   └── query.go          # CVE matching + version comparison logic
│   └── models/models.go      # Data structures
├── .env                      # Database credentials
├── go.mod / go.sum           # Go module files
└── README.md