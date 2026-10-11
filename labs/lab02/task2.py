"""Аналізатор DNS-транзакцій для виявлення підозрілих запитів."""

from __future__ import annotations

import argparse
import csv
import logging
import math
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

LONG_LABEL_RE = re.compile(r"^[a-z0-9-]{20,}$", re.IGNORECASE)
SUSPICIOUS_TLD_RE = re.compile(r"\.(?:xyz|top|tk|gq|ml)$", re.IGNORECASE)
CSV_FIELDS = ("timestamp", "client_ip", "domain", "query_type")
CSV_FIELD_ALIASES = {
    "timestamp": "timestamp",
    "clientip": "client_ip",
    "domain": "domain",
    "querytype": "query_type",
}


@dataclass(frozen=True)
class DNSQuery:
    """Один запис DNS-журналу."""

    timestamp: datetime
    client_ip: str
    domain: str
    query_type: str


@dataclass(frozen=True)
class DNSAlert:
    """Підозрілий DNS-запит і причина спрацювання."""

    timestamp: str
    client_ip: str
    domain: str
    query_type: str
    reason: str


def _parse_log(path: Path) -> list[DNSQuery]:
    queries: list[DNSQuery] = []
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        field_names = {
            name.strip().casefold().replace("_", ""): name
            for name in (reader.fieldnames or ())
            if name
        }
        columns = {
            canonical: field_names[alias]
            for alias, canonical in CSV_FIELD_ALIASES.items()
            if alias in field_names
        }
        missing = set(CSV_FIELDS) - set(columns)
        if missing:
            raise ValueError(
                "У DNS CSV відсутні колонки: " + ", ".join(sorted(missing))
            )
        for line_number, row in enumerate(reader, start=2):
            try:
                queries.append(
                    DNSQuery(
                        datetime.fromisoformat(
                            row[columns["timestamp"]].strip()
                        ),
                        row[columns["client_ip"]].strip(),
                        row[columns["domain"]].strip().rstrip(".").lower(),
                        row[columns["query_type"]].strip().upper(),
                    )
                )
            except (AttributeError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"Некоректний DNS-запис у рядку {line_number}: {exc}"
                ) from exc
            if not all(
                (
                    queries[-1].client_ip,
                    queries[-1].domain,
                    queries[-1].query_type,
                )
            ):
                raise ValueError(
                    f"Порожнє поле DNS-запису в рядку {line_number}"
                )
    return queries


def _load_blacklist(path: Path) -> set[str]:
    return {
        line.strip().rstrip(".").lower()
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def analyze_queries(
    queries: list[DNSQuery],
    blacklist: set[str],
    min_domain_len: int = 50,
) -> tuple[Counter[str], list[DNSAlert]]:
    """Повертає статистику типів і записи, що відповідають правилам."""
    if min_domain_len < 1:
        raise ValueError("min_domain_len має бути додатним")

    query_types: Counter[str] = Counter()
    alerts: list[DNSAlert] = []
    for query in queries:
        query_types[query.query_type] += 1
        reasons: list[str] = []
        if query.domain in blacklist:
            reasons.append("blacklist")
        labels = query.domain.split(".")
        if any(LONG_LABEL_RE.fullmatch(label) for label in labels[:-1]):
            reasons.append("long_subdomain")
        if SUSPICIOUS_TLD_RE.search(query.domain):
            reasons.append("suspicious_tld")
        if len(query.domain) >= min_domain_len and query.query_type == "TXT":
            reasons.append("long_txt_domain")
        if (
            len(labels) >= 3
            and len(labels[0]) >= 12
            and _entropy(labels[0]) >= 3.5
        ):
            reasons.append("high_entropy_subdomain")
        if reasons:
            alerts.append(
                DNSAlert(
                    query.timestamp.isoformat(),
                    query.client_ip,
                    query.domain,
                    query.query_type,
                    ";".join(dict.fromkeys(reasons)),
                )
            )
    return query_types, alerts


def _write_report(path: Path, alerts: list[DNSAlert]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=tuple(asdict(alerts[0]).keys())
            if alerts
            else ("timestamp", "client_ip", "domain", "query_type", "reason"),
        )
        writer.writeheader()
        writer.writerows(asdict(alert) for alert in alerts)


def analyze(args: argparse.Namespace) -> int:
    """Виконує аудит із аргументами командного рядка."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
        filename=args.log_file,
        filemode="w",
        encoding="utf-8" if args.log_file else None,
        force=True,
    )
    log = logging.getLogger(__name__)
    try:
        log.info("Parsing DNS log file %s...", args.dns_log)
        queries = _parse_log(args.dns_log)
        blacklist = _load_blacklist(args.blacklist)
        query_types, alerts = analyze_queries(
            queries, blacklist, args.min_domain_len
        )
        log.info("Processed %d DNS query records.", len(queries))
        print("=== Query Type Breakdown ===")
        for query_type, count in sorted(query_types.items()):
            share = count / len(queries) * 100 if queries else 0
            print(f"{query_type:<5}: {count:>5} ({share:.1f}%)")
        print("=== Suspicious DNS Activity ===")
        for alert in alerts:
            if "blacklist" in alert.reason:
                label = "BLACKMATCH"
            else:
                label = "DGA-DETECT"
            print(
                f"[{label}] Client {alert.client_ip} queried "
                f"{alert.domain}: {alert.reason}"
            )
            log.warning(
                "Suspicious DNS query from %s for %s (%s)",
                alert.client_ip,
                alert.domain,
                alert.reason,
            )
        _write_report(args.out_csv, alerts)
        log.info("Suspicious records exported to %s", args.out_csv)
        print(f"[INFO] Suspicious records exported to {args.out_csv}")
    except (OSError, UnicodeError, csv.Error, ValueError) as exc:
        log.error("DNS analysis failed: %s", exc)
        print(f"Помилка: {exc}")
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Створює CLI з командами demo та analyze."""
    parser = argparse.ArgumentParser(
        description="Лабораторна робота № 2: кібербезпекові CLI-утиліти"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="демонстрація ООП-моделі (Завдання 1)")
    analyze_parser = commands.add_parser(
        "analyze", help="аналіз CSV-журналу DNS (варіант 8)"
    )
    analyze_parser.add_argument("--dns-log", type=Path, required=True)
    analyze_parser.add_argument("--blacklist", type=Path, required=True)
    analyze_parser.add_argument("--out-csv", type=Path, required=True)
    analyze_parser.add_argument("--min-domain-len", type=int, default=50)
    analyze_parser.add_argument("--log-file", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Точка входу CLI."""
    parser = build_parser()
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        arguments = ["demo"]
    args = parser.parse_args(arguments)
    if args.command == "demo":
        from .task1 import run_demo

        run_demo()
        return 0
    return analyze(args)
