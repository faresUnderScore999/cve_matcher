# CVE Matcher

A Go-based tool that matches assets (network devices, servers, endpoints) against CVE records from a local NVD database to identify vulnerable software versions, create tickets, and notify asset owners.

## Architecture

The tool connects to two databases:

- **NeonDB** (remote) — Contains asset inventory: `assets`, `server_assets`, `endpoint_assets`, `network_device_assets`, output table `affected_assets`, and ticket table `cve_ticket`.
- **NvdDB** (local) — Contains CVE data from the [NVD JSON data feeds](https://github.com/fkie-cad/nvd-json-data-feeds) in a normalized schema: `cve_records`, `cve_affected`, `cve_versions`.

## Prerequisites

- Go 1.22+
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

- `assets` — Core asset table with `asset_id` (UUID), `status`, `owner_email`, `hostname`, `ip_address`
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
    product    TEXT,
    cvss_score DOUBLE PRECISION,
    severity   VARCHAR(20),
    matched_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(asset_id, cve_id)
;
```

### cve_ticket Table

The ticket table stores CVEs matched to assets with SLA tracking:
```sql
CREATE TABLE cve_ticket (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    UUID NOT NULL,
    cve_id      VARCHAR(20) NOT NULL,
    status      VARCHAR(20) NOT NULL,
    priority    VARCHAR(10),
    assigned_to VARCHAR(100),
    descreption TEXT,
    due_date    TIMESTAMP,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMP,
    closed_at   TIMESTAMP,
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

# Resend API Key for email notifications
RESEND_API_KEY=re_xxxxxxxxx
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
  -e RESEND_API_KEY="re_xxxxxxxxx" \
  cve-matcher
```

The tool will:
1. Connect to both databases
2. Fetch all active assets from NeonDB (network devices, servers, endpoints)
3. For each asset, query the NvdDB using indexed `vendor`/`product` lookups
4. Evaluate version constraints from `cve_versions` to determine if the asset is affected
5. Insert matched findings into `affected_assets`
6. Create tickets in `cve_ticket` for new findings (skipping duplicates)
7. Send email notifications to asset owners for newly created tickets

## How the Matching Works

### Query Path

(base on pre-existing content — kept intact for brevity)

### Ticket and Notification Pipeline

After findings are inserted into `affected_assets`, the tool:

1. **Creates tickets** (`cve_ticket` table) with:
   - `status = 'OPEN'`
   - Priority based on severity (CRITICAL→P1, HIGH→P2, MEDIUM→P3, LOW→P4)
   - Due date = now + SLA days (CRITICAL=7d, HIGH=14d, MEDIUM=30d, LOW=60d)
   - Description summarizing the finding

2. **Sends email** via Resend API to the asset owner (`owner_email`) with:
   - CVE ID, severity, CVSS score
   - Product name and version
   - Hostname and IP address
   - Priority and days to resolve

Only newly created tickets trigger email notifications (duplicates from previous runs are skipped via `ON CONFLICT DO NOTHING`).

## Project Structure

The code is organized by pipeline stage:

```
Fetch → Transform → Lookup CVEs → Match → Write → Ticket → Notify

├── cmd/matcher/main.go       # Entry point + orchestration
├── pkd/
│   ├── db/database.go        # Database connection management (NeonDB + NvdDB)
│   ├── matcher/
│   │   ├── fetcher.go        # Stage 1: Fetch assets from NeonDB
│   │   ├── os_mapping.go     # Stage 2a: Map OS names → CPE vendor/product pairs
│   │   ├── software_parser.go# Stage 2b: Parse installed_software JSONB
│   │   ├── cve_lookup.go     # Stage 3: Query NvdDB for CVEs
│   │   ├── matcher.go        # Stage 4: In-memory CVE matching
│   │   ├── version.go        # Stage 4b: Version constraint evaluation
│   │   ├── writer.go         # Stage 5: Insert findings into affected_assets
│   │   ├── ticket.go         # Stage 6a: Create tickets in cve_ticket
│   │   └── notifier.go       # Stage 6b: Send email notifications
│   └── models/models.go      # Data structures shared across pipeline stages
├── .env                      # Database credentials + API keys
├── go.mod / go.sum           # Go module files
└── README.md