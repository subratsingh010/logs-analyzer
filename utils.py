"""Small shared base and constants for the Kubernetes log analyzer."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping


STATUS_RUNNING = "running"
STATUS_CRASHED = "crashed"
STATUS_DEGRADED = "degraded"
STATUS_UNKNOWN = "unknown"

EVENT_CRASH = "crash"
EVENT_DEGRADED = "degraded"
EVENT_RESTART = "restart"
EVENT_RUNNING = "running"
EVENT_ACTIVITY = "activity"

DEFAULT_IDENTITY_KEYS = (
    "workload",
    "workload_name",
    "pod",
    "pod_name",
    "container",
    "container_name",
    "node",
    "node_name",
)

REPORT_HEADERS = (
    "status",
    "namespace",
    "pod",
    "container",
    "node",
    "pod_ip",
    "node_ip",
    "cluster",
    "service",
    "last_crash_time",
    "crash_reason",
    "crash_load",
    "latest_observed_load",
    "last_seen_timestamp",
    "restart_count",
)

IST = timezone(timedelta(hours=5, minutes=30))

TIMESTAMP_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)"
)
KEY_VALUE_RE = re.compile(
    r"\b(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(?P<value>[A-Za-z0-9_.:/@-]+)"
)
LOAD_RE = re.compile(
    r"\b(?P<key>load|load_avg|cpu|cpu_pct|cpu_percent|mem|memory|memory_pct|memory_percent)"
    r"\s*[:=]\s*(?P<value>\d+(?:\.\d+)?)(?:%)?\b",
    re.IGNORECASE,
)
RESTART_COUNT_RE = re.compile(
    r"\b(?:restart_count|restarts|restartCount)\s*[:=]\s*(?P<count>\d+)\b",
    re.IGNORECASE,
)
CRASH_RE = re.compile(
    r"\b(crash(?:ed|ing|loopbackoff)?|crashloopbackoff|panic|fatal|terminated|"
    r"oomkilled|oom|back-?off|segfault|core dumped|exit(?:ed)? with code [1-9]\d*)\b",
    re.IGNORECASE,
)
DEGRADED_RE = re.compile(
    r"\b(degraded|unhealthy|not ready|readiness probe failed|liveness probe failed|"
    r"high latency|timeout|timeouts|error rate|throttl(?:ed|ing)|disk pressure|memory pressure)\b",
    re.IGNORECASE,
)
RESTART_RE = re.compile(r"\b(restart(?:ed|ing)?|restarted container)\b", re.IGNORECASE)
RUNNING_RE = re.compile(
    r"\b(running|healthy|started|ready|listening|available|online|up)\b",
    re.IGNORECASE,
)
CRASH_REASON_RE = re.compile(
    r"\b(?:reason|error|exception|cause)\s*[:=]\s*(?P<reason>[^,;|]+)",
    re.IGNORECASE,
)
QUICK_KEEP_RE = re.compile(
    r"(namespace|ns|pod|pod_name|pod_ip|podip|container|container_name|node|node_name|node_ip|"
    r"nodeip|host_ip|ip|cluster|service|workload|crash|panic|fatal|terminated|oom|backoff|"
    r"restart|degraded|unhealthy|running|healthy|started|ready|load|cpu|mem|\{)",
    re.IGNORECASE,
)


class BaseLogParser:
    """Reusable base for concrete streaming log analyzers."""

    def parse_line(self, line: str, line_number: int) -> dict[str, Any] | None:
        """Parse one log line into a normalized event, or return None."""

        raise NotImplementedError("Subclasses should implement parse_line().")

    @classmethod
    def build_arg_parser(cls) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="Analyze one large Kubernetes-based .log file and print a per-workload health report."
        )
        parser.add_argument("log_file", help="Exactly one .log file.")
        parser.add_argument("--metadata", help="Optional JSON metadata mapping file.")
        parser.add_argument("--identity-key", action="append", dest="identity_keys")
        parser.add_argument("--json-report", help="Optional path to write JSON output.")
        parser.add_argument("--csv-report", help="Optional path to write CSV output.")
        parser.add_argument("--no-table", action="store_true", help="Do not print terminal table.")
        parser.add_argument("--crash-load-window", type=int, default=300)
        parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
        return parser

    @staticmethod
    def configure_logging(verbose: bool) -> None:
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.WARNING,
            format="%(levelname)s %(name)s: %(message)s",
        )

    def require_log_file(self, path: str | Path) -> Path:
        log_path = Path(path)
        if not log_path.is_file():
            raise FileNotFoundError(f"Log file not found: {log_path}")
        if log_path.suffix != ".log":
            raise ValueError(f"Only .log files are supported: {log_path}")
        return log_path

    def is_relevant(self, line: str) -> bool:
        return bool(QUICK_KEEP_RE.search(line))

    def classify(self, message: str) -> str:
        if CRASH_RE.search(message):
            return EVENT_CRASH
        if DEGRADED_RE.search(message):
            return EVENT_DEGRADED
        if RESTART_RE.search(message):
            return EVENT_RESTART
        if RUNNING_RE.search(message):
            return EVENT_RUNNING
        return EVENT_ACTIVITY

    def parse_timestamp_value(self, value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            except (OSError, OverflowError, ValueError):
                return None

        text = str(value).strip().strip("[]").replace("Z", "+00:00")
        match = TIMESTAMP_RE.search(text)
        if match:
            text = match.group("ts").replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", text):
            text = text[:-5] + text[-5:-2] + ":" + text[-2:]
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)

    def parse_text_load(
        self,
        message: str,
        timestamp: datetime | None,
        line_number: int,
    ) -> dict[str, Any] | None:
        load: dict[str, Any] = {"timestamp": timestamp, "line_number": line_number}
        for match in LOAD_RE.finditer(message):
            key = match.group("key").lower()
            try:
                value = float(match.group("value"))
            except ValueError:
                continue
            if key in {"load", "load_avg"}:
                load["load"] = value
            elif key in {"cpu", "cpu_pct", "cpu_percent"}:
                load["cpu"] = value
            elif key in {"mem", "memory", "memory_pct", "memory_percent"}:
                load["memory"] = value
        return load if any(key in load for key in ("load", "cpu", "memory")) else None

    def nested_get(self, payload: Mapping[str, Any], dotted_key: str) -> Any:
        current: Any = payload
        if dotted_key in payload:
            return payload[dotted_key]
        for part in dotted_key.split("."):
            if not isinstance(current, Mapping) or part not in current:
                return None
            current = current[part]
        return current

    def first_json_value(self, payload: Mapping[str, Any], names: tuple[str, ...]) -> Any:
        for name in names:
            value = self.nested_get(payload, name)
            if value not in (None, ""):
                return value
        return None

    def normalize_identity_key(self, key: str) -> str | None:
        normalized = {
            "ns": "namespace",
            "namespace_name": "namespace",
            "pod_name": "pod",
            "podip": "pod_ip",
            "pod_ip": "pod_ip",
            "container_name": "container",
            "node_name": "node",
            "nodeip": "node_ip",
            "node_ip": "node_ip",
            "host_ip": "node_ip",
            "ip": "pod_ip",
            "cluster_name": "cluster",
            "app": "service",
        }.get(key.lower(), key.lower())
        allowed = {
            "workload",
            "workload_name",
            "namespace",
            "pod",
            "pod_ip",
            "container",
            "node",
            "node_ip",
            "cluster",
            "service",
        }
        return normalized if normalized in allowed else None

    def format_timestamp(self, value: datetime | None) -> str | None:
        return None if value is None else value.astimezone(IST).isoformat()

    def format_load(self, load: Mapping[str, Any] | None) -> str:
        if not load:
            return "-"
        parts = []
        if load.get("load") is not None:
            parts.append(f"load={load['load']:g}")
        if load.get("cpu") is not None:
            parts.append(f"cpu={load['cpu']:g}")
        if load.get("memory") is not None:
            parts.append(f"mem={load['memory']:g}")
        return ",".join(parts) if parts else "-"

    def write_json_report(self, path: str | Path, data: Any) -> None:
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def write_csv_report(self, path: str | Path, headers: tuple[str, ...], rows: list[dict[str, Any]]) -> None:
        with Path(path).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(headers))
            writer.writeheader()
            writer.writerows(rows)
