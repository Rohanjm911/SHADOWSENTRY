# Privacy-First Engineering & Data Sanitization — SHADOWSENTRY

**SHADOWSENTRY: Invisible Threats. Visible Intelligence.**

---

## 1. Architectural Philosophy

SHADOWSENTRY was engineered under the core tenet of **Data Minimization by Default**. Security monitoring tools too often become secondary attack surfaces by archiving unencrypted credentials, PII, and full application session dumps.

SHADOWSENTRY treats all network traffic as potentially sensitive and strictly separates observable protocol metadata from application payloads.

---

## 2. Storage Boundaries & Database Architecture

All data captured or processed by SHADOWSENTRY is confined to a local SQLite database:
- **Location**: `%LOCALAPPDATA%\ShadowSentry\shadowsentry.db`.
- **Mode**: Write-Ahead Logging (WAL) for crash resistance and fast non-blocking concurrent queries.
- **Access Control**: Readable only by the local operating system user account under standard Windows DACLs.

### 2.1. Tables & Schemas
1. **`monitoring_sessions`**:
   - Stores session start time, stop time, interface name, backend mode (`npcap`, `raw_socket`, `laboratory`), total packet count, and byte count.
2. **`security_events`**:
   - Stores deterministic forensic detections.
   - Fields: `id`, `session_id`, `rule_id`, `severity`, `title`, `description`, `evidence_json`, `uncertainty`, `recommendations`, `status` (`Active`, `Resolved`, `Dismissed`), and `created_at`.
3. **`dns_records`**:
   - Observable DNS queries (Domain, Record Type, Query Time, Shannon Entropy).
4. **`honeypot_interactions`**:
   - Probes against simulated honeypots (`service_name`, `source_ip`, `source_port`, `interaction_type`, `headers_snippet`).
   - *Note*: Cleartext credentials and request bodies exceeding 128 bytes are permanently discarded prior to insertion.
5. **`app_settings`**:
   - Key-value configuration store for heuristic thresholds and UI preferences.

---

## 3. Data Sanitization & Export Engine

When a security analyst exports events or monitoring sessions via the **Event History** or **Reports** screens, the Rust backend executes sanitization before generating files:

### 3.1. Sanitization Protocol
1. **Strip Internal Keys**: Internal database auto-increment IDs and sensitive Windows user paths (e.g. `C:\Users\Username\...`) are redacted.
2. **ISO 8601 UTC Standardization**: All epoch timestamps are normalized to unambiguous ISO 8601 UTC strings.
3. **Evidence Validation**: Evidence JSON strings are parsed and filtered to ensure only protocol metadata (IP, port, protocol, packet count) is included.
4. **No Raw Payloads**: Even if payload capture was temporarily enabled during a debugging session, the export routines filter out any raw binary or hex strings.

### 3.2. Formats
- **Sanitized JSON**: Machine-readable array of structured event objects formatted with two-space indentation.
- **Sanitized CSV**: Standard RFC 4180 compliant comma-separated values with escaped quotes and standard headers.

---

## 4. User-Controlled Deletion & Retention

### 4.1. Configurable Retention
Users can configure retention from 1 to 365 days in the **Settings** view. A periodic background cleanup routine executes:
```sql
DELETE FROM security_events WHERE created_at < ?;
DELETE FROM monitoring_sessions WHERE stopped_at IS NOT NULL AND stopped_at < ?;
DELETE FROM honeypot_interactions WHERE created_at < ?;
DELETE FROM dns_records WHERE query_time < ?;
```

### 4.2. Instant Complete Wipe
Under **Settings -> Storage & Retention Management**, clicking **"Wipe Entire Database"** executes:
```sql
DELETE FROM security_events;
DELETE FROM monitoring_sessions;
DELETE FROM honeypot_interactions;
DELETE FROM dns_records;
VACUUM;
```
The `VACUUM` command immediately truncates the database file, reclaims disk blocks from the filesystem, and prevents forensic recovery of deleted rows.
