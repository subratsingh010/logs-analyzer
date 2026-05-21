# Log Health Analyzer

Production-style Python project for analyzing one very large `.log` file with streaming I/O. It reads the file line by line, keeps only per-workload state in memory, and prints the latest health report in the terminal.

## Files

- `main.py` - CLI entrypoint, orchestration, and the concrete `LogAnalyzer` parser.
- `utils.py` - shared constants, base parser helpers, reusable parsing utilities, JSON/CSV writers.
- `example_kubernetes.log` - sample central log file with mixed text and JSON lines.
- `example_metadata.json` - optional metadata enrichment example.

## Requirements

- Python 3.10+
- No external Python packages required.
- Input must be exactly one file ending in `.log`.

## How To Run

Print the terminal report:

```bash
python3 main.py example_kubernetes.log
```

Run with optional metadata:

```bash
python3 main.py example_kubernetes.log --metadata example_metadata.json
```

Write JSON and CSV reports:

```bash
python3 main.py example_kubernetes.log \
  --metadata example_metadata.json \
  --json-report report.json \
  --csv-report report.csv
```

Write only files and skip the terminal table:

```bash
python3 main.py example_kubernetes.log --json-report report.json --no-table
```

Use a custom identity field priority:

```bash
python3 main.py example_kubernetes.log --identity-key pod --identity-key container
```

Show debug logging:

```bash
python3 main.py example_kubernetes.log --verbose
```

## Main Features

- Streams one `.log` file line by line, so multi-GB files are not loaded into memory.
- Accepts one file only; directories, glob patterns, multiple inputs, and non-`.log` files are rejected.
- Parses text lines, CRI-style lines, and JSON log lines inside a `.log` file.
- Detects workload identity from `namespace`, `pod`, `container`, `node`, `pod_ip`, `node_ip`, `cluster`, and `service` fields when present.
- Keeps each workload unique by `namespace/pod/container` when pod information exists. If pod is missing, it falls back to `namespace/container/node`.
- Detects latest status as `running`, `crashed`, `degraded`, or `unknown`.
- Reports only the latest derived status per workload.
- Tracks last crash time, crash reason, crash load, latest load, last seen timestamp, and restart count.
- Infers crash load from nearby load lines when the crash line does not contain load directly.
- Prints a summary with total, active, inactive, running, crashed, degraded, and unknown counts.
- Uses IST timestamps in terminal, JSON, and CSV output.

`active` means the workload's latest status is `running`.

`inactive` means the workload's latest status is `crashed`, `degraded`, or `unknown`.

## Example Input

Text log:

```text
2026-05-21T08:02:00Z namespace=payments pod=api-7d9c8 container=api node=node-a pod_ip=10.42.1.12 node_ip=192.168.10.21 load=2.4 cpu=82 mem=70
2026-05-21T08:02:30Z namespace=payments pod=api-7d9c8 container=api node=node-a crashed reason=OOMKilled restart_count=2
```

CRI-style log:

```text
2026-05-21T08:12:00Z stdout F [auth/login-7b6:api@node-a] fatal error=db_connection_lost load=2.8 cpu=89 mem=78
```

JSON log:

```json
{"timestamp":"2026-05-21T08:39:00Z","namespace":"search","pod":"indexer-0","container":"indexer","node":"node-f","pod_ip":"10.42.7.10","node_ip":"192.168.10.26","status":"fatal","reason":"disk_pressure","load":3.1,"cpu":92,"memory":81}
```

## Example Output

```text
SUMMARY  total=19  active=17  inactive=2  running=17  crashed=0  degraded=2  unknown=0
STATUS    NAMESPACE  POD        CONTAINER  NODE    POD_IP       NODE_IP        LAST_CRASH_TIME            CRASH_REASON  LATEST_OBSERVED_LOAD    LAST_SEEN_TIMESTAMP
--------  ---------  ---------  ---------  ------  -----------  -------------  -------------------------  ------------  ----------------------  -------------------------
running   payments   api-7d9c8  api        node-a  10.42.1.12   192.168.10.21  2026-05-21T13:32:00+05:30  OOMKilled     load=0.8,cpu=20,mem=42  2026-05-21T13:33:00+05:30
```

## How Status Is Decided

- `crashed`: latest important event is a crash-like event such as `crashed`, `panic`, `fatal`, `terminated`, `oomkilled`, `backoff`, or non-zero exit.
- `degraded`: latest important event is a degraded signal such as `unhealthy`, `not ready`, probe failure, timeout, throttling, disk pressure, or memory pressure.
- `running`: latest important event is healthy/running activity, or there is recent activity after an older crash/degraded event.
- `unknown`: no usable evidence exists for the workload.

This means the report shows current/latest derived status, not historical status.

## Optional Metadata File

Metadata can enrich rows when some fields are missing from the log line.

Example:

```json
{
  "payments/api-7d9c8/api": {
    "namespace": "payments",
    "pod": "api-7d9c8",
    "container": "api",
    "cluster": "prod-east",
    "service": "checkout",
    "pod_ip": "10.42.1.12",
    "node_ip": "192.168.10.21"
  }
}
```

The best metadata key is:

```text
namespace/pod/container
```

## How To Extend Parsing

For small pattern changes, edit the parser constants in `main.py`:

- Add JSON field aliases in `LogAnalyzer.JSON_FIELDS`.
- Add text identity patterns by extending `BRACKET_ID_RE`, `PREFIX_ID_RE`, or the key/value names accepted by `normalize_identity_key()` in `utils.py`.
- Add crash, degraded, restart, or running keywords by updating the compiled regex constants in `utils.py`.

For a new parser style later, create a new class that inherits from `BaseLogParser` and implements `parse_line()` with the same normalized event shape:

```python
{
    "key": "namespace/pod/container",
    "context": {"namespace": "...", "pod": "...", "container": "..."},
    "timestamp": parsed_datetime_or_none,
    "line_number": line_number,
    "event_type": "running | crash | degraded | restart | activity",
    "message": original_or_normalized_message,
    "load": {"load": 1.2, "cpu": 40.0, "memory": 70.0},
    "crash_reason": "OOMKilled",
    "restart_count": 2,
}
```

The existing processing flow can stay the same if the new parser returns this event structure.

## Performance Notes

- File reading uses buffered line-by-line streaming.
- Regex patterns are compiled once at import time.
- Irrelevant lines are skipped early with a quick keyword filter.
- Memory grows with the number of unique workloads, not the number of log lines.
