#!/usr/bin/env python3
"""CLI and concrete Kubernetes log analyzer."""

from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Mapping

from utils import (
    CRASH_RE,
    CRASH_REASON_RE,
    DEFAULT_IDENTITY_KEYS,
    EVENT_ACTIVITY,
    EVENT_CRASH,
    EVENT_DEGRADED,
    EVENT_RESTART,
    EVENT_RUNNING,
    KEY_VALUE_RE,
    REPORT_HEADERS,
    RESTART_COUNT_RE,
    STATUS_CRASHED,
    STATUS_DEGRADED,
    STATUS_RUNNING,
    STATUS_UNKNOWN,
    BaseLogParser,
)


LOGGER = logging.getLogger(__name__)


class LogAnalyzer(BaseLogParser):
    """Parser designed to analyze Kubernetes-based .log files using streaming I/O."""

    # Kubernetes parser design: these patterns and JSON field aliases parse
    # Kubernetes text, CRI-style, and structured JSON log lines.
    CRI_PREFIX_RE = re.compile(
        r"^(?P<timestamp>\S+)\s+(?:stdout|stderr)\s+[A-Z]\s+(?P<message>.*)$"
    )
    BRACKET_ID_RE = re.compile(
        r"\[(?:(?P<namespace>[A-Za-z0-9_.-]+)/)?(?P<pod>[A-Za-z0-9_.-]+)"
        r"(?:[:/](?P<container>[A-Za-z0-9_.-]+))?(?:@(?P<node>[A-Za-z0-9_.-]+))?\]"
    )
    PREFIX_ID_RE = re.compile(
        r"^(?:(?P<namespace>[A-Za-z0-9_.-]+)/)?(?P<pod>[A-Za-z0-9_.-]+)/"
        r"(?P<container>[A-Za-z0-9_.-]+)\s+"
    )
    JSON_FIELDS: Mapping[str, tuple[str, ...]] = {
        "cluster": ("cluster", "cluster_name", "kubernetes.cluster", "kubernetes.cluster_name"),
        "namespace": ("namespace", "ns", "namespace_name", "kubernetes.namespace_name"),
        "pod": ("pod", "pod_name", "kubernetes.pod_name"),
        "pod_ip": ("pod_ip", "podIP", "pod_ip_address", "ip", "kubernetes.pod_ip", "kubernetes.podIP"),
        "container": ("container", "container_name", "kubernetes.container_name"),
        "node": ("node", "node_name", "kubernetes.host", "host.name"),
        "node_ip": ("node_ip", "nodeIP", "host_ip", "kubernetes.node_ip", "kubernetes.nodeIP", "host.ip"),
        "service": ("service", "service.name", "app", "kubernetes.labels.app"),
        "timestamp": ("timestamp", "time", "@timestamp", "ts", "date"),
        "message": ("message", "msg", "log", "event.message"),
        "status": ("status", "phase", "state", "reason"),
        "restart_count": ("restart_count", "restarts", "restartCount", "kubernetes.restart_count"),
        "crash_reason": ("crash_reason", "reason", "error", "exception"),
    }
    HEADERS = REPORT_HEADERS

    def __init__(
        self,
        log_file: str | Path,
        metadata_file: str | None = None,
        identity_keys: tuple[str, ...] = DEFAULT_IDENTITY_KEYS,
        crash_load_window_seconds: int = 300,
        crash_load_window_lines: int = 200,
    ) -> None:
        self.log_file = self.require_log_file(log_file)
        self.metadata = self._load_metadata_mapping(metadata_file)
        self.identity_keys = identity_keys
        self.crash_load_window_seconds = crash_load_window_seconds
        self.crash_load_window_lines = crash_load_window_lines
        self.states: dict[str, dict[str, Any]] = {}
        self.skipped_lines = 0

    def parse_line(self, line: str, line_number: int) -> dict[str, Any] | None:
        """Parse one Kubernetes log line into a normalized event."""

        if not self.is_relevant(line):
            return None
        record = self._prepare_record(line, line_number)
        if record is None:
            return None

        context = self._extract_identity(record)
        key = self._first_identity_value(context, self.identity_keys) or self._workload_key(
            context.get("namespace"),
            context.get("pod"),
            context.get("container"),
            context.get("node"),
        )
        if not key:
            return None

        timestamp = self._extract_timestamp(record)
        message = self._extract_message(record)
        event_type = self.classify(message)
        load = self._extract_load(record, timestamp)
        return {
            "key": key,
            "context": context,
            "timestamp": timestamp,
            "line_number": line_number,
            "event_type": event_type,
            "message": message,
            "load": load,
            "crash_reason": self._extract_crash_reason(record, message) if event_type == EVENT_CRASH else None,
            "restart_count": self._extract_restart_count(record, message),
        }

    def update_state(self, event: dict[str, Any]) -> None:
        """Update per-workload state from one parsed event."""

        context = self._enrich_context(event["key"], event["context"])
        key = context.get("key") or event["key"]
        state = self.states.setdefault(key, self._new_state(key, context))
        state["context"] = self._merge_context(state["context"], context)

        self._touch(state, "last_seen", event)
        if event.get("load"):
            self._observe_load(state, event["load"])
            self._try_pending_crash_load(state, event["load"])

        restart_count = event.get("restart_count")
        if restart_count is not None:
            state["restart_count"] = max(state["restart_count"], restart_count)

        event_type = event["event_type"]
        if event_type == EVENT_CRASH:
            self._record_crash(state, event)
        elif event_type == EVENT_DEGRADED:
            state["degraded_count"] += 1
            self._touch(state, "last_degraded", event)
            state["evidence"] = self._evidence(event)
        elif event_type == EVENT_RESTART:
            if restart_count is None:
                state["restart_count"] += 1
            self._touch(state, "last_running", event)
            state["evidence"] = self._evidence(event)
        elif event_type == EVENT_RUNNING:
            self._touch(state, "last_running", event)
            state["evidence"] = self._evidence(event)
        elif event_type == EVENT_ACTIVITY:
            self._touch(state, "last_activity", event)

    def process_file(self) -> list[dict[str, Any]]:
        """Stream the .log file and return final report rows."""

        with self.log_file.open("rt", encoding="utf-8", errors="replace", buffering=1024 * 1024) as handle:
            for line_number, line in enumerate(handle, start=1):
                try:
                    event = self.parse_line(line.rstrip("\n"), line_number)
                except Exception as exc:
                    LOGGER.debug("Skipping malformed line %s: %s", line_number, exc)
                    self.skipped_lines += 1
                    continue
                if event is None:
                    self.skipped_lines += 1
                    continue
                self.update_state(event)

        for state in self.states.values():
            state["status"] = self._derive_status(state)
        return [self._report_row(state) for state in sorted(self.states.values(), key=lambda item: item["key"])]

    def print_report(
        self,
        rows: list[dict[str, Any]],
        json_report: str | None = None,
        csv_report: str | None = None,
        show_table: bool = True,
    ) -> None:
        """Print terminal table and optionally write JSON/CSV reports."""

        summary = self._summary(rows)
        if show_table:
            print(self._summary_text(summary))
            print(self._table(rows))
        if json_report:
            self.write_json_report(json_report, {"summary": summary, "workloads": rows})
        if csv_report:
            self.write_csv_report(csv_report, self.HEADERS, rows)

    def _prepare_record(self, line: str, line_number: int) -> dict[str, Any] | None:
        stripped = line.lstrip()
        if stripped.startswith("{"):
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                return None
            if not isinstance(payload, Mapping):
                return None
            return {"line": line, "line_number": line_number, "payload": payload}

        match = self.CRI_PREFIX_RE.match(line)
        if match:
            return {
                "line": line,
                "line_number": line_number,
                "message": match.group("message"),
                "timestamp_hint": self.parse_timestamp_value(match.group("timestamp")),
            }
        return {"line": line, "line_number": line_number, "message": line, "timestamp_hint": None}

    def _extract_identity(self, record: Mapping[str, Any]) -> dict[str, Any]:
        values = self._identity_from_payload(record.get("payload"))
        values.update(self._identity_from_text(str(record.get("message") or record.get("line") or "")))
        return values

    def _extract_timestamp(self, record: Mapping[str, Any]) -> Any:
        payload = record.get("payload")
        if isinstance(payload, Mapping):
            parsed = self.parse_timestamp_value(self.first_json_value(payload, self.JSON_FIELDS["timestamp"]))
            if parsed:
                return parsed
        return record.get("timestamp_hint") or self.parse_timestamp_value(record.get("line"))

    def _extract_message(self, record: Mapping[str, Any]) -> str:
        payload = record.get("payload")
        if isinstance(payload, Mapping):
            status = str(self.first_json_value(payload, self.JSON_FIELDS["status"]) or "")
            message = str(self.first_json_value(payload, self.JSON_FIELDS["message"]) or "")
            return f"{status} {message}".strip()
        return str(record.get("message") or "")

    def _extract_load(self, record: Mapping[str, Any], timestamp: Any) -> dict[str, Any] | None:
        payload = record.get("payload")
        line_number = int(record["line_number"])
        if isinstance(payload, Mapping):
            load = self._parse_json_load(payload, timestamp, line_number)
            if load:
                return load
        return self.parse_text_load(self._extract_message(record), timestamp, line_number)

    def _extract_restart_count(self, record: Mapping[str, Any], message: str) -> int | None:
        payload = record.get("payload")
        if isinstance(payload, Mapping):
            parsed = self._parse_optional_int(self.first_json_value(payload, self.JSON_FIELDS["restart_count"]))
            if parsed is not None:
                return parsed
        return self._parse_restart_count(message)

    def _extract_crash_reason(self, record: Mapping[str, Any], message: str) -> str | None:
        payload = record.get("payload")
        if isinstance(payload, Mapping):
            value = self.first_json_value(payload, self.JSON_FIELDS["crash_reason"])
            if value not in (None, ""):
                return str(value)
        return self._parse_crash_reason(message)

    def _parse_json_load(self, payload: Mapping[str, Any], timestamp: Any, line_number: int) -> dict[str, Any] | None:
        load = {
            "timestamp": timestamp,
            "line_number": line_number,
            "load": self._parse_json_number(payload, ("load", "load_avg", "metrics.load")),
            "cpu": self._parse_json_number(payload, ("cpu", "cpu_percent", "metrics.cpu", "metrics.cpu_percent")),
            "memory": self._parse_json_number(
                payload,
                ("mem", "memory", "memory_percent", "metrics.memory", "metrics.memory_percent"),
            ),
        }
        return load if any(load.get(key) is not None for key in ("load", "cpu", "memory")) else None

    def _parse_json_number(self, payload: Mapping[str, Any], fields: tuple[str, ...]) -> float | None:
        for field in fields:
            value = self.nested_get(payload, field)
            if value is None:
                continue
            try:
                return float(str(value).rstrip("%"))
            except ValueError:
                continue
        return None

    def _parse_optional_int(self, value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _parse_restart_count(self, message: str) -> int | None:
        match = RESTART_COUNT_RE.search(message)
        return int(match.group("count")) if match else None

    def _parse_crash_reason(self, message: str) -> str | None:
        explicit = CRASH_REASON_RE.search(message)
        if explicit:
            return explicit.group("reason").strip()
        keyword = CRASH_RE.search(message)
        return keyword.group(1).lower() if keyword else None

    def _identity_from_payload(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            return {}
        values: dict[str, Any] = {}
        for field in ("cluster", "namespace", "pod", "pod_ip", "container", "node", "node_ip", "service"):
            value = self.first_json_value(payload, self.JSON_FIELDS[field])
            if value not in (None, ""):
                values[field] = str(value)
        labels = self.nested_get(payload, "kubernetes.labels")
        if isinstance(labels, Mapping) and not values.get("service"):
            service = labels.get("app") or labels.get("app.kubernetes.io/name")
            if service:
                values["service"] = str(service)
        return values

    def _identity_from_text(self, message: str) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for pattern in (self.BRACKET_ID_RE, self.PREFIX_ID_RE):
            match = pattern.search(message)
            if match:
                values.update({key: value for key, value in match.groupdict().items() if value})
        for match in KEY_VALUE_RE.finditer(message):
            key = self.normalize_identity_key(match.group("key"))
            if key:
                values[key] = match.group("value")
        return values

    def _first_identity_value(self, values: Mapping[str, str | None], keys: tuple[str, ...]) -> str | None:
        for key in keys:
            normalized = self.normalize_identity_key(key) or key
            value = values.get(normalized)
            if value:
                return value
        return None

    def _workload_key(
        self,
        namespace: str | None,
        pod: str | None,
        container: str | None,
        node: str | None,
    ) -> str | None:
        if pod:
            return "/".join((namespace or "_", pod, container or "_"))
        if container or node:
            return "/".join((namespace or "_", container or "_", node or "_"))
        return None

    def _load_metadata_mapping(self, path: str | Path | None) -> dict[str, dict[str, str]]:
        if not path:
            return {}
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not read metadata mapping {path}: {exc}") from exc

        entries: dict[str, dict[str, str]] = {}
        iterable = raw.items() if isinstance(raw, Mapping) else enumerate(raw if isinstance(raw, list) else [])
        for default_key, item in iterable:
            if not isinstance(item, Mapping):
                continue
            context = {
                "namespace": self._string_or_none(item.get("namespace") or item.get("ns")),
                "pod": self._string_or_none(item.get("pod") or item.get("pod_name")),
                "pod_ip": self._string_or_none(item.get("pod_ip") or item.get("podIP") or item.get("ip")),
                "container": self._string_or_none(item.get("container") or item.get("container_name")),
                "node": self._string_or_none(item.get("node") or item.get("node_name")),
                "node_ip": self._string_or_none(item.get("node_ip") or item.get("nodeIP") or item.get("host_ip")),
                "cluster": self._string_or_none(item.get("cluster") or item.get("cluster_name")),
                "service": self._string_or_none(item.get("service") or item.get("app")),
            }
            context["key"] = (
                self._string_or_none(item.get("workload") or item.get("workload_key"))
                or self._workload_key(context["namespace"], context["pod"], context["container"], context["node"])
                or str(default_key)
            )
            for alias in (str(default_key), context["key"]):
                entries[alias] = context
        return entries

    def _merge_context(self, base: dict[str, Any], extra: Mapping[str, Any]) -> dict[str, Any]:
        merged = dict(base)
        for key in ("namespace", "pod", "pod_ip", "container", "node", "node_ip", "cluster", "service"):
            if not merged.get(key) and extra.get(key):
                merged[key] = extra[key]
        return merged

    def _string_or_none(self, value: Any) -> str | None:
        return None if value in (None, "") else str(value)

    def _new_state(self, key: str, context: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "key": key,
            "context": dict(context),
            "status": STATUS_UNKNOWN,
            "last_crash_time": None,
            "last_crash_line": None,
            "crash_reason": None,
            "crash_load": None,
            "latest_load": None,
            "last_seen_time": None,
            "last_seen_line": None,
            "last_running_time": None,
            "last_running_line": None,
            "last_degraded_time": None,
            "last_degraded_line": None,
            "last_activity_time": None,
            "last_activity_line": None,
            "restart_count": 0,
            "crash_count": 0,
            "degraded_count": 0,
            "evidence": None,
            "pending_crash_time": None,
            "pending_crash_line": None,
        }

    def _enrich_context(self, key: str, context: Mapping[str, Any]) -> dict[str, Any]:
        candidates = (
            key,
            self._workload_key(context.get("namespace"), context.get("pod"), context.get("container"), context.get("node")),
            context.get("pod"),
            context.get("container"),
            context.get("node"),
        )
        enriched = {"key": key, **dict(context)}
        for candidate in candidates:
            if candidate and candidate in self.metadata:
                enriched = self._merge_context(enriched, self.metadata[candidate])
                enriched["key"] = enriched.get("key") or key
                break
        return enriched

    def _newer_observation(
        self,
        candidate_time: Any,
        candidate_line: int | None,
        current_time: Any,
        current_line: int | None,
    ) -> bool:
        if candidate_time and current_time:
            return candidate_time > current_time
        if candidate_time and current_time is None:
            return True
        if candidate_time is None and current_time:
            return False
        if candidate_line is None:
            return False
        return current_line is None or candidate_line > current_line

    def _load_is_near(
        self,
        load: Mapping[str, Any] | None,
        timestamp: Any,
        line_number: int | None,
        time_window_seconds: int,
        line_window: int,
    ) -> bool:
        if not load:
            return False
        load_time = load.get("timestamp")
        load_line = load.get("line_number")
        if timestamp and load_time:
            return abs((load_time - timestamp).total_seconds()) <= time_window_seconds
        if line_number is not None and load_line is not None:
            return abs(load_line - line_number) <= line_window
        return False

    def _touch(self, state: dict[str, Any], prefix: str, event: Mapping[str, Any]) -> None:
        if self._newer_observation(
            event.get("timestamp"),
            event.get("line_number"),
            state.get(f"{prefix}_time"),
            state.get(f"{prefix}_line"),
        ):
            state[f"{prefix}_time"] = event.get("timestamp")
            state[f"{prefix}_line"] = event.get("line_number")

    def _observe_load(self, state: dict[str, Any], load: Mapping[str, Any]) -> None:
        latest = state.get("latest_load")
        if latest is None or self._newer_observation(
            load.get("timestamp"),
            load.get("line_number"),
            latest.get("timestamp"),
            latest.get("line_number"),
        ):
            state["latest_load"] = dict(load)

    def _try_pending_crash_load(self, state: dict[str, Any], load: Mapping[str, Any]) -> None:
        if state.get("crash_load"):
            return
        if state.get("pending_crash_time") is None and state.get("pending_crash_line") is None:
            return
        if self._load_is_near(
            load,
            state.get("pending_crash_time"),
            state.get("pending_crash_line"),
            self.crash_load_window_seconds,
            self.crash_load_window_lines,
        ):
            state["crash_load"] = dict(load)
            state["pending_crash_time"] = None
            state["pending_crash_line"] = None

    def _record_crash(self, state: dict[str, Any], event: Mapping[str, Any]) -> None:
        state["crash_count"] += 1
        if not self._newer_observation(
            event.get("timestamp"),
            event.get("line_number"),
            state.get("last_crash_time"),
            state.get("last_crash_line"),
        ):
            return
        state["last_crash_time"] = event.get("timestamp")
        state["last_crash_line"] = event.get("line_number")
        state["crash_reason"] = event.get("crash_reason")
        state["evidence"] = self._evidence(event)
        state["crash_load"] = event.get("load")
        if not state["crash_load"] and self._load_is_near(
            state.get("latest_load"),
            event.get("timestamp"),
            event.get("line_number"),
            self.crash_load_window_seconds,
            self.crash_load_window_lines,
        ):
            state["crash_load"] = dict(state["latest_load"])
        if not state["crash_load"]:
            state["pending_crash_time"] = event.get("timestamp")
            state["pending_crash_line"] = event.get("line_number")

    def _derive_status(self, state: Mapping[str, Any]) -> str:
        if state.get("last_seen_line") is None:
            return STATUS_UNKNOWN
        ok_pair = self._newer_pair(
            (state.get("last_running_time"), state.get("last_running_line")),
            (state.get("last_activity_time"), state.get("last_activity_line")),
        )
        problem_pair = self._newer_pair(
            (state.get("last_crash_time"), state.get("last_crash_line")),
            (state.get("last_degraded_time"), state.get("last_degraded_line")),
        )
        crash_pair = (state.get("last_crash_time"), state.get("last_crash_line"))
        degraded_pair = (state.get("last_degraded_time"), state.get("last_degraded_line"))
        if problem_pair == crash_pair and self._pair_newer_or_equal(crash_pair, ok_pair):
            return STATUS_CRASHED
        if problem_pair == degraded_pair and self._pair_newer_or_equal(degraded_pair, ok_pair):
            return STATUS_DEGRADED
        return STATUS_RUNNING

    def _newer_pair(self, left: tuple[Any, Any], right: tuple[Any, Any]) -> tuple[Any, Any]:
        return left if self._newer_observation(left[0], left[1], right[0], right[1]) else right

    def _pair_newer_or_equal(self, left: tuple[Any, Any], right: tuple[Any, Any]) -> bool:
        if right == (None, None):
            return left != (None, None)
        return left == right or self._newer_observation(left[0], left[1], right[0], right[1])

    def _report_row(self, state: Mapping[str, Any]) -> dict[str, Any]:
        context = state["context"]
        return {
            "status": state["status"],
            "namespace": context.get("namespace"),
            "pod": context.get("pod"),
            "container": context.get("container"),
            "node": context.get("node"),
            "pod_ip": context.get("pod_ip"),
            "node_ip": context.get("node_ip"),
            "cluster": context.get("cluster"),
            "service": context.get("service"),
            "last_crash_time": self.format_timestamp(state.get("last_crash_time")),
            "crash_reason": state.get("crash_reason"),
            "crash_load": self.format_load(state.get("crash_load")),
            "latest_observed_load": self.format_load(state.get("latest_load")),
            "last_seen_timestamp": self.format_timestamp(state.get("last_seen_time")),
            "restart_count": state.get("restart_count", 0),
        }

    def _table(self, rows: list[dict[str, Any]]) -> str:
        table_rows = [[self._display(row.get(header)) for header in self.HEADERS] for row in rows]
        widths = [
            max(len(value) for value in column)
            for column in zip(tuple(header.upper() for header in self.HEADERS), *table_rows, strict=False)
        ]
        header = "  ".join(name.upper().ljust(width) for name, width in zip(self.HEADERS, widths, strict=False))
        rule = "  ".join("-" * width for width in widths)
        body = [
            "  ".join(value.ljust(width) for value, width in zip(row, widths, strict=False))
            for row in table_rows
        ]
        return "\n".join([header, rule, *body])

    def _summary(self, rows: list[dict[str, Any]]) -> dict[str, int]:
        running = sum(1 for row in rows if row.get("status") == STATUS_RUNNING)
        crashed = sum(1 for row in rows if row.get("status") == STATUS_CRASHED)
        degraded = sum(1 for row in rows if row.get("status") == STATUS_DEGRADED)
        unknown = sum(1 for row in rows if row.get("status") == STATUS_UNKNOWN)
        inactive = crashed + degraded + unknown
        return {
            "total": len(rows),
            "active": running,
            "inactive": inactive,
            "running": running,
            "crashed": crashed,
            "degraded": degraded,
            "unknown": unknown,
        }

    def _summary_text(self, summary: Mapping[str, int]) -> str:
        return (
            "SUMMARY  "
            f"total={summary['total']}  "
            f"active={summary['active']}  "
            f"inactive={summary['inactive']}  "
            f"running={summary['running']}  "
            f"crashed={summary['crashed']}  "
            f"degraded={summary['degraded']}  "
            f"unknown={summary['unknown']}"
        )

    def _display(self, value: Any) -> str:
        return "-" if value in (None, "") else str(value)

    def _evidence(self, event: Mapping[str, Any], limit: int = 140) -> str:
        message = str(event.get("message") or "").replace("\t", " ").strip()
        if len(message) > limit:
            message = message[: limit - 3] + "..."
        return f"line {event.get('line_number')}: {message}"


def main(argv: list[str] | None = None) -> int:
    args = LogAnalyzer.build_arg_parser().parse_args(argv)
    LogAnalyzer.configure_logging(args.verbose)

    try:
        analyzer = LogAnalyzer(
            log_file=args.log_file,
            metadata_file=args.metadata,
            identity_keys=tuple(args.identity_keys) if args.identity_keys else DEFAULT_IDENTITY_KEYS,
            crash_load_window_seconds=max(0, args.crash_load_window),
        )
        rows = analyzer.process_file()
        analyzer.print_report(
            rows,
            json_report=args.json_report,
            csv_report=args.csv_report,
            show_table=not args.no_table,
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
