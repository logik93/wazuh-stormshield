#!/usr/bin/env python3
"""Read a QNAP volume table over SNMPv3 and print one JSON record per volume."""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys


# NAS-MIB: volumeTableEntry and sysVolumeEntryEx, with counters in bytes.
TABLES = (
    (".1.3.6.1.4.1.24681.1.4.1.1.1.2.3.2.1", 8, 3, 4),
    (".1.3.6.1.4.1.24681.1.3.17.1", 2, 4, 5),
)
VARBIND = re.compile(r"^(\.[\d.]+) = (STRING|Counter64):\s*(.*)$")


def parse_volumes(output, table):
    prefix, name_column, total_column, free_column = table
    volumes = {}
    for line in output.splitlines():
        match = VARBIND.fullmatch(line)
        if not match:
            continue
        oid, value_type, value = match.groups()
        value = value.strip()
        if not oid.startswith(prefix + "."):
            continue
        column, _, index = oid[len(prefix) + 1 :].partition(".")
        if not index.isdecimal():
            continue
        if column == str(name_column) and value_type == "STRING":
            name = value.strip().removeprefix('"').removesuffix('"')
            volumes.setdefault(index, {})["name"] = name
        if column in (str(total_column), str(free_column)) and value_type == "Counter64" and value.isdecimal():
            key = "total" if column == str(total_column) else "free"
            volumes.setdefault(index, {})[key] = int(value)
    return volumes


def read_volumes(target, config_dir):
    environ = os.environ.copy()
    environ["LC_ALL"] = "C.UTF-8"
    if config_dir:
        environ["SNMPCONFPATH"] = str(config_dir.resolve())
    for table in TABLES:
        result = subprocess.run(
            ["snmpwalk", "-v3", "-l", "authPriv", "-On", "-t", "3", "-r", "1", target, table[0]],
            env=environ, capture_output=True, text=True, errors="replace", timeout=30,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or f"snmpwalk zakończył się kodem {result.returncode}.")
        rows = parse_volumes(result.stdout, table)
        volumes = {
            index: row for index, row in rows.items()
            if row.get("total", 0) > 0 and 0 <= row.get("free", -1) <= row["total"]
        }
        if volumes:
            return volumes
    raise RuntimeError("NAS nie zwrócił poprawnych liczników rozmiaru woluminów z NAS-MIB.")


def display_size(size):
    for power, unit in ((4, "TiB"), (3, "GiB"), (2, "MiB"), (1, "KiB")):
        scale = 1024**power
        if size >= scale:
            return f"{size / scale:.2f} {unit}"
    return f"{size} B"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="adres lub nazwa NAS-a dla Net-SNMP")
    parser.add_argument("--device", required=True, help="unikalna nazwa NAS-a w dashboardzie")
    parser.add_argument("--snmp-config-dir", type=Path, help="katalog z prywatnym plikiem snmp.conf")
    args = parser.parse_args()
    if not args.target or args.target.startswith("-"):
        parser.error("adres NAS-a nie może być pusty ani zaczynać się od myślnika")
    if not args.device.strip():
        parser.error("podaj nazwę NAS-a")
    if args.snmp_config_dir and not (args.snmp_config_dir / "snmp.conf").is_file():
        parser.error("w podanym katalogu brakuje pliku snmp.conf")
    volumes = read_volumes(args.target, args.snmp_config_dir)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    for index, row in sorted(volumes.items(), key=lambda item: int(item[0])):
        name = row.get("name") or f"Wolumin {index}"
        print(json.dumps({
            "integration": "qnap_volume_capacity",
            "qnap_capacity": {
                "volume": f"{args.device} / {name} [#{index}]",
                "total": display_size(row["total"]),
                "free": display_size(row["free"]),
                "free_percent": f"{100 * row['free'] / row['total']:.1f}%",
                "measured_at": timestamp,
            },
        }, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"QNAP: {error}", file=sys.stderr)
        sys.exit(1)
