# Database Schema Documentation

## Overview

The pentest-automation platform uses PostgreSQL with UUID primary keys and JSONB columns for flexible data storage. All tables include automatic timestamps (created_at, updated_at).

## Tables

### Scans

Main scan orchestration table.

**Columns:**
- `id` (UUID, PK) - Unique scan identifier
- `name` (String) - Human-readable scan name
- `status` (Enum) - Current status: pending, running, paused, completed, failed, stopped
- `pipeline_config` (JSONB) - Pipeline configuration
- `started_at` (DateTime) - Scan start time
- `completed_at` (DateTime) - Scan completion time
- `total_targets` (Integer) - Total number of targets
- `completed_targets` (Integer) - Number of completed targets
- `failed_targets` (Integer) - Number of failed targets
- `total_findings` (Integer) - Total findings count
- `critical_findings` (Integer) - Critical severity count
- `high_findings` (Integer) - High severity count
- `medium_findings` (Integer) - Medium severity count
- `low_findings` (Integer) - Low severity count
- `risk_score` (Float) - Overall risk score
- `error_count` (Integer) - Number of errors
- `created_at` (DateTime) - Record creation time
- `updated_at` (DateTime) - Last update time

**Relationships:**
- One-to-many with Targets
- One-to-many with Findings
- One-to-many with Checkpoints

### Targets

Individual scan targets.

**Columns:**
- `id` (UUID, PK) - Unique target identifier
- `scan_id` (UUID, FK) - Reference to parent scan
- `raw_value` (String) - Original target value
- `normalized_value` (String) - Normalized target value
- `target_type` (Enum) - Type: web, api, ip, domain, network, cloud, database, ssh, smtp, ftp, rdp, iot, mobile_app
- `classification` (JSONB) - Detailed classification
- `status` (Enum) - Status: pending, scanning, completed, failed, skipped, blacklisted
- `current_stage` (String) - Current pipeline stage
- `findings_count` (Integer) - Number of findings
- `risk_score` (Float) - Target risk score
- `blacklisted` (Boolean) - Blacklist flag
- `blacklist_reason` (String) - Reason for blacklisting
- `scan_started_at` (DateTime) - Target scan start
- `scan_completed_at` (DateTime) - Target scan completion
- `individual_report_path` (String) - Path to individual report
- `metadata` (JSONB) - Additional metadata
- `error_log` (JSONB) - Error logs
- `created_at` (DateTime) - Record creation time
- `updated_at` (DateTime) - Last update time

**Relationships:**
- Many-to-one with Scan
- One-to-many with Findings
- One-to-many with Checkpoints

### Findings

Security vulnerabilities and issues.

**Columns:**
- `id` (UUID, PK) - Unique finding identifier
- `scan_id` (UUID, FK) - Reference to scan
- `target_id` (UUID, FK) - Reference to target
- `title` (String) - Finding title
- `description` (Text) - Detailed description
- `severity` (Enum) - Severity: critical, high, medium, low, info
- `finding_type` (String) - Type (SQLi, XSS, RCE, etc.)
- `category` (String) - Category
- `cwe_id` (String) - CWE identifier
- `cve_id` (String) - CVE identifier
- `cvss_score` (Float) - CVSS score
- `affected_component` (String) - Affected component
- `evidence` (JSONB) - Evidence data
- `remediation` (Text) - Remediation steps
- `remediation_effort` (Enum) - Effort: low, medium, high
- `remediation_priority` (Integer) - Priority (1-10)
- `tool` (String) - Discovery tool
- `confidence` (Integer) - Confidence level (0-100)
- `false_positive_probability` (Float) - False positive probability
- `fingerprint` (String) - Deduplication fingerprint
- `sources` (JSONB) - Discovery sources
- `discovered_at` (DateTime) - Discovery time
- `created_at` (DateTime) - Record creation time
- `updated_at` (DateTime) - Last update time

**Relationships:**
- Many-to-one with Scan
- Many-to-one with Target

### Blacklist Entries

Blocked targets and patterns.

**Columns:**
- `id` (UUID, PK) - Unique entry identifier
- `entry_type` (Enum) - Type: ip, domain, network, pattern, asn
- `value` (String, Unique) - Blacklisted value
- `reason` (Text) - Blacklist reason
- `source` (String) - Source: manual, corporate, automatic
- `severity` (String) - Severity level
- `active` (Boolean) - Active status
- `expires_at` (DateTime) - Expiration time
- `hit_count` (Integer) - Number of hits
- `last_hit` (DateTime) - Last hit time
- `created_at` (DateTime) - Record creation time
- `updated_at` (DateTime) - Last update time

### Checkpoints

Recovery and state management.

**Columns:**
- `id` (UUID, PK) - Unique checkpoint identifier
- `scan_id` (UUID, FK) - Reference to scan
- `target_id` (UUID, FK) - Reference to target
- `stage` (String) - Current stage
- `completed_stages` (JSONB) - Completed stages
- `state_data` (JSONB) - State data for recovery
- `created_at` (DateTime) - Record creation time
- `updated_at` (DateTime) - Last update time

**Relationships:**
- Many-to-one with Scan
- Many-to-one with Target

## Indexes

### Scans
- `ix_scans_status` - For filtering by status

### Targets
- `ix_targets_scan_id` - Foreign key lookup
- `ix_targets_normalized_value` - Target lookup
- `ix_targets_target_type` - Type filtering
- `ix_targets_status` - Status filtering
- `ix_targets_blacklisted` - Blacklist filtering

### Findings
- `ix_findings_scan_id` - Foreign key lookup
- `ix_findings_target_id` - Foreign key lookup
- `ix_findings_severity` - Severity filtering
- `ix_findings_fingerprint` - Deduplication
- `ix_findings_cwe_id` - CWE lookup
- `ix_findings_cve_id` - CVE lookup

### Blacklist Entries
- `ix_blacklist_entries_value` - Unique constraint and lookup
- `ix_blacklist_entries_entry_type` - Type filtering
- `ix_blacklist_entries_active` - Active filtering

### Checkpoints
- `ix_checkpoints_scan_id` - Foreign key lookup
- `ix_checkpoints_target_id` - Foreign key lookup
- `ix_checkpoints_stage` - Stage filtering

## Migration

To apply the database schema:

```bash
# Using Docker
docker-compose exec backend alembic upgrade head

# Using Makefile
make migrate

# Locally
alembic upgrade head
```

To create a new migration:

```bash
# Using Docker
docker-compose exec backend alembic revision --autogenerate -m "description"

# Using Makefile
make migration

# Locally
alembic revision --autogenerate -m "description"
```

## JSONB Fields

### pipeline_config (Scans)
Stores pipeline configuration including:
- Enabled stages
- Tool configurations
- Timeout settings
- Concurrency limits

### classification (Targets)
Stores target classification:
- Technology stack
- Frameworks detected
- Protocols
- Additional metadata

### metadata (Targets)
Stores additional target information:
- Discovery source
- Tags
- Custom fields

### error_log (Targets)
Stores error information:
- Error messages
- Stack traces
- Timestamps

### evidence (Findings)
Stores finding evidence:
- Request/response data
- Screenshots
- Proof of concept
- Additional context

### sources (Findings)
Stores discovery source information:
- Tool names
- Timestamps
- Confidence levels

### completed_stages (Checkpoints)
Tracks completed pipeline stages:
- Stage names
- Completion timestamps
- Results

### state_data (Checkpoints)
Stores recovery state:
- Current progress
- Partial results
- Tool states
