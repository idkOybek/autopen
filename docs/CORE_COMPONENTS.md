# Core Components Documentation

## Overview

Core components provide essential functionality for target classification, deduplication, blacklist management, error handling, and state management.

## Components

### 1. TargetClassifier

**Location:** `backend/core/target_classifier.py`

**Purpose:** Classify, normalize, and enrich scan targets.

**Key Methods:**

- `classify_target(raw_target: str) -> dict`
  - Determines target type (web, api, ip, domain, network, cloud, database, ssh, smtp, ftp, rdp, iot, mobile_app)
  - Returns detailed classification including protocol, port, path

- `normalize_target(raw_target: str, target_type: str) -> str`
  - Normalizes targets for deduplication
  - Lowercase domains, standardize URLs, validate IPs

- `enrich_target(target: dict) -> dict`
  - Placeholder for enrichment (DNS lookups, port scanning, tech detection)

- `get_tools_for_target(target_type: str) -> list`
  - Returns appropriate tools for target type
  - Uses TOOL_MAPPING configuration

**Tool Mapping:**

```python
TOOL_MAPPING = {
    TargetType.WEB: ["nuclei", "nikto", "gobuster", "sqlmap", "xsstrike", "wpscan", "whatweb"],
    TargetType.API: ["nuclei", "ffuf", "arjun", "postman", "swagger-scanner"],
    TargetType.IP: ["nmap", "masscan", "nuclei"],
    TargetType.DOMAIN: ["subfinder", "amass", "dnsrecon", "dig", "nmap"],
    # ... more mappings
}
```

**Example Usage:**

```python
from backend.core import TargetClassifier

classifier = TargetClassifier()

# Classify target
result = classifier.classify_target("https://api.example.com/v1")
print(result["target_type"])  # "api"

# Normalize target
normalized = classifier.normalize_target("HTTPS://Example.COM/path/", "web")
print(normalized)  # "https://example.com/path"

# Get tools
tools = classifier.get_tools_for_target("web")
print(tools)  # ["nuclei", "nikto", "gobuster", ...]
```

---

### 2. Deduplicator

**Location:** `backend/core/deduplicator.py`

**Purpose:** Remove duplicate targets and findings.

**Key Methods:**

- `deduplicate_targets(targets: list) -> tuple[list, list]`
  - Returns (unique_targets, duplicates)
  - Uses normalized values and target types for hashing

- `generate_target_hash(target: dict) -> str`
  - Creates MD5 hash from normalized_value:target_type

- `deduplicate_findings(findings: list) -> list`
  - Merges duplicate findings
  - Combines metadata and sources

- `generate_finding_fingerprint(finding: dict) -> str`
  - Creates SHA256 fingerprint from finding_type:severity:title:target_id:component:port

- `merge_finding_metadata(existing: dict, duplicate: dict)`
  - Increases confidence to max value
  - Merges sources dictionaries
  - Updates false_positive_probability to minimum

**Example Usage:**

```python
from backend.core import Deduplicator

dedup = Deduplicator()

# Deduplicate targets
targets = [
    {"normalized_value": "example.com", "target_type": "domain"},
    {"normalized_value": "example.com", "target_type": "domain"},
]
unique, dupes = dedup.deduplicate_targets(targets)
print(len(unique))  # 1

# Deduplicate findings
findings = [
    {
        "title": "XSS",
        "severity": "high",
        "target_id": "123",
        "affected_component": "/api/user",
        "confidence": 80,
        "sources": {"nuclei": True}
    },
    {
        "title": "XSS",
        "severity": "high",
        "target_id": "123",
        "affected_component": "/api/user",
        "confidence": 90,
        "sources": {"nikto": True}
    }
]
unique_findings = dedup.deduplicate_findings(findings)
print(unique_findings[0]["confidence"])  # 90 (max)
print(len(unique_findings[0]["sources"]))  # 2 (merged)
```

---

### 3. BlacklistManager

**Location:** `backend/core/blacklist_manager.py`

**Purpose:** Filter forbidden targets and manage blacklist.

**Key Methods:**

- `load_blacklist()`
  - Loads active blacklist entries from database into memory
  - Compiles regex patterns
  - Organizes by type: ip, domain, network, pattern, asn

- `is_blacklisted(target: str) -> tuple[bool, str]`
  - Returns (is_blocked, reason)
  - Checks IPs, domains, networks, patterns

- `filter_targets(targets: list) -> tuple[list, list]`
  - Returns (allowed, blacklisted)
  - Marks blacklisted targets with reason

- `add_entry(entry_type: str, value: str, reason: str)`
  - Adds new blacklist entry
  - Reloads cache

- `check_ip_in_network(ip: str, networks: list) -> tuple[bool, str]`
  - Checks if IP belongs to blacklisted networks (CIDR)

- `check_subdomain(domain: str, blacklisted_domains: list) -> tuple[bool, str]`
  - Checks if domain is subdomain of blacklisted domain

**Example Usage:**

```python
from backend.core import BlacklistManager

manager = BlacklistManager(db_session)
await manager.load_blacklist()

# Check single target
is_blocked, reason = await manager.is_blacklisted("192.168.1.1")
print(f"Blocked: {is_blocked}, Reason: {reason}")

# Filter targets
targets = [
    {"normalized_value": "example.com"},
    {"normalized_value": "malicious.com"},
]
allowed, blocked = await manager.filter_targets(targets)
print(f"Allowed: {len(allowed)}, Blocked: {len(blocked)}")

# Add entry
await manager.add_entry(
    "domain",
    "malicious.com",
    "Known malware distributor",
    source="manual",
    severity="high"
)
```

---

### 4. ErrorHandler

**Location:** `backend/core/error_handler.py`

**Purpose:** Centralized error handling and recovery strategies.

**Error Categories:**

- `NETWORK` - Connection, DNS, SSL errors
- `TOOL` - Tool execution, command not found
- `TARGET` - Invalid target, blacklisted
- `SYSTEM` - Memory, disk, resource exhaustion
- `DATABASE` - Database, SQL errors
- `TIMEOUT` - Timeout errors
- `VALIDATION` - Validation errors
- `PERMISSION` - Permission, access denied
- `UNKNOWN` - Uncategorized errors

**Recovery Actions:**

- `RETRY_WITH_BACKOFF` - Exponential backoff retry
- `RETRY_IMMEDIATE` - Immediate retry
- `SKIP_TARGET` - Skip current target
- `SKIP_TOOL` - Skip current tool
- `REDUCE_PARALLELISM` - Reduce concurrency
- `FAIL_SCAN` - Fail entire scan
- `CONTINUE` - Continue without action
- `REPORT_AND_CONTINUE` - Log and continue

**Key Methods:**

- `handle_error(error: Exception, context: dict) -> dict`
  - Returns error entry with category, recovery_action, is_critical

- `categorize_error(error: Exception) -> ErrorCategory`
  - Categorizes based on exception type and message

- `get_recovery_action(category: ErrorCategory, error: Exception) -> RecoveryAction`
  - Returns appropriate recovery action

- `is_critical(category: ErrorCategory) -> bool`
  - Returns if error is critical (SYSTEM, DATABASE)

- `should_retry(category: ErrorCategory, retry_count: int) -> bool`
  - Checks against max_retries for category

- `get_backoff_delay(retry_count: int, base_delay: float) -> float`
  - Calculates exponential backoff: base_delay * (2 ** retry_count)

**Example Usage:**

```python
from backend.core import ErrorHandler, ErrorCategory

handler = ErrorHandler()

# Handle error
try:
    # ... operation
    pass
except ConnectionError as e:
    error_entry = handler.handle_error(e, {
        "scan_id": "123",
        "target_id": "456",
        "tool": "nmap"
    })

    print(error_entry["category"])  # "network"
    print(error_entry["recovery_action"])  # "retry_with_backoff"
    print(error_entry["is_critical"])  # False

    # Check if should retry
    if handler.should_retry(ErrorCategory.NETWORK, retry_count=1):
        delay = handler.get_backoff_delay(retry_count=1)
        await asyncio.sleep(delay)
        # retry...
```

---

### 5. StateManager

**Location:** `backend/core/state_manager.py`

**Purpose:** Scan state and checkpoint management using Redis.

**Redis Key Patterns:**

- `scan:{scan_id}:status` - Scan status
- `scan:{scan_id}:checkpoints:{target_id}` - Target checkpoints
- `scan:{scan_id}:state` - Complete scan state
- `scan:{scan_id}:metadata:{key}` - Custom metadata
- `scan:{scan_id}:counter:{name}` - Counters
- `lock:{lock_name}` - Distributed locks

**Key Methods:**

- `create_checkpoint(scan_id: str, target_id: str, stage: str, data: dict)`
  - Creates recovery checkpoint with TTL (default 24h)

- `load_checkpoint(scan_id: str, target_id: str) -> dict`
  - Loads checkpoint or returns None

- `update_scan_status(scan_id: str, status: str)`
  - Updates scan status in Redis

- `get_scan_status(scan_id: str) -> str`
  - Gets current status

- `save_scan_state(scan_id: str, state: dict)`
  - Saves complete scan state

- `get_scan_state(scan_id: str) -> dict`
  - Loads complete state

- `delete_scan_state(scan_id: str)`
  - Deletes all scan-related keys

- `increment_counter(scan_id: str, counter_name: str, amount: int) -> int`
  - Increments counter atomically

- `acquire_lock(lock_name: str, ttl: int) -> bool`
  - Acquires distributed lock

- `release_lock(lock_name: str) -> bool`
  - Releases lock

**Example Usage:**

```python
from backend.core import StateManager
import redis.asyncio as aioredis

redis_client = aioredis.from_url("redis://localhost:6379/0")
manager = StateManager(redis_client)

# Create checkpoint
await manager.create_checkpoint(
    "scan-123",
    "target-456",
    "reconnaissance",
    {"completed": ["nmap"], "pending": ["nikto"]}
)

# Update status
await manager.update_scan_status("scan-123", "running")

# Save state
await manager.save_scan_state("scan-123", {
    "total_targets": 100,
    "completed_targets": 50,
    "current_stage": "scanning"
})

# Increment counter
count = await manager.increment_counter("scan-123", "findings_count")

# Acquire lock
if await manager.acquire_lock("scan:123:target:456"):
    try:
        # ... critical section
        pass
    finally:
        await manager.release_lock("scan:123:target:456")

# Load checkpoint for recovery
checkpoint = await manager.load_checkpoint("scan-123", "target-456")
if checkpoint:
    stage = checkpoint["stage"]
    data = checkpoint["data"]
    # ... resume from checkpoint

# Cleanup
await manager.delete_scan_state("scan-123")
```

---

## Integration Example

```python
from backend.core import (
    TargetClassifier,
    Deduplicator,
    BlacklistManager,
    ErrorHandler,
    StateManager
)

# Initialize components
classifier = TargetClassifier()
deduplicator = Deduplicator()
blacklist_manager = BlacklistManager(db_session)
error_handler = ErrorHandler()
state_manager = StateManager(redis_client)

# Load blacklist
await blacklist_manager.load_blacklist()

# Process targets
raw_targets = ["https://example.com", "192.168.1.1", "api.test.com"]

# Classify
targets = []
for raw in raw_targets:
    classification = classifier.classify_target(raw)
    normalized = classifier.normalize_target(raw, classification["target_type"])
    targets.append({
        "raw_value": raw,
        "normalized_value": normalized,
        "target_type": classification["target_type"],
        "classification": classification
    })

# Deduplicate
unique_targets, duplicates = deduplicator.deduplicate_targets(targets)

# Filter blacklist
allowed_targets, blacklisted = await blacklist_manager.filter_targets(unique_targets)

# Process with error handling
for target in allowed_targets:
    try:
        # Save checkpoint
        await state_manager.create_checkpoint(
            scan_id,
            str(target["id"]),
            "starting",
            {}
        )

        # Get tools for target
        tools = classifier.get_tools_for_target(target["target_type"])

        # Run tools...

    except Exception as e:
        # Handle error
        error_entry = error_handler.handle_error(e, {
            "scan_id": scan_id,
            "target_id": str(target["id"]),
            "target": target["normalized_value"]
        })

        if error_entry["recovery_action"] == "skip_target":
            continue
```

---

## Best Practices

1. **TargetClassifier**
   - Always normalize before storing
   - Use get_tools_for_target for tool selection
   - Enrich targets when detailed info needed

2. **Deduplicator**
   - Deduplicate targets before blacklist check
   - Always deduplicate findings before storage
   - Use fingerprints for finding correlation

3. **BlacklistManager**
   - Load blacklist at scan start
   - Reload after adding entries
   - Update hit counts for analytics

4. **ErrorHandler**
   - Always pass context to handle_error
   - Respect recovery actions
   - Use backoff for retries
   - Check is_critical before continuing

5. **StateManager**
   - Create checkpoints at stage transitions
   - Use locks for concurrent operations
   - Clean up state after scan completion
   - Use counters for statistics
   - Set appropriate TTLs

---

## Error Handling Flow

```
Error Occurs
    ↓
Categorize Error
    ↓
Determine Recovery Action
    ↓
Is Critical? → Yes → Fail Scan
    ↓ No
Check Max Retries
    ↓
Should Retry? → Yes → Calculate Backoff → Retry
    ↓ No
Execute Recovery Action (Skip Target/Tool/Continue)
    ↓
Log Error
    ↓
Continue Scan
```
