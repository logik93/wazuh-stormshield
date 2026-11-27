#!/usr/bin/env python3
"""Exercise the custom rules and decoders with the official Wazuh manager."""

import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "wazuh/wazuh-manager:4.14.5"
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PHASE = re.compile(r"^\*\*Phase ([123]):.*$", re.MULTILINE)
ATTRIBUTE = re.compile(r"^\s*([\w .]+): '(.*)'\s*$", re.MULTILINE)


def correlation_cases():
    """Keep the events in one logtest session and vary the correlation keys."""
    def event(name, device, ip, payload, rule, level):
        return {
            "name": name,
            "log": f"id=firewall fw={device} src={ip} {payload}",
            "decoder": "stormshield-sns",
            "rule": rule,
            "level": level,
            "fields": {},
        }

    failure = "error=1 logtype=auth"
    cases = [
        event(f"Uwierzytelnianie: przed progiem {i}", "auth-fw", "192.0.2.100", failure, 110504, 6)
        for i in range(1, 5)
    ]
    cases += [
        event("Uwierzytelnianie: inna zapora", "other-fw", "192.0.2.100", failure, 110504, 6),
        event("Uwierzytelnianie: inne źródło", "auth-fw", "192.0.2.101", failure, 110504, 6),
        event("Uwierzytelnianie: sukces pomiędzy błędami", "auth-fw", "192.0.2.100", "error=0 logtype=auth", 110500, 0),
        event("Uwierzytelnianie: osiągnięty próg", "auth-fw", "192.0.2.100", 'msg="Authentication failed" logtype=auth', 110508, 10),
    ]
    block = "action=block dst=198.51.100.99 logtype=filter"
    cases += [
        event(f"Blokada: przed progiem {i}", "filter-fw", "192.0.2.102", block, 110501, 4)
        for i in range(1, 10)
    ]
    cases += [
        event("Blokada: inna zapora", "other-fw", "192.0.2.102", block, 110501, 4),
        event("Blokada: inne źródło", "filter-fw", "192.0.2.103", block, 110501, 4),
        event("Blokada: osiągnięty próg", "filter-fw", "192.0.2.102", block, 110509, 8),
    ]
    return cases


def attributes(section):
    return dict(ATTRIBUTE.findall(section))


def check_event(case, sections):
    decoded = attributes(sections.get("2", ""))
    matched = attributes(sections.get("3", ""))
    expected = {
        "decoder": case["decoder"],
        "rule": None if case["rule"] is None else str(case["rule"]),
        "level": None if case["level"] is None else str(case["level"]),
        **case["fields"],
    }
    if "description" in case:
        expected["description"] = case["description"]
    actual = {
        **decoded,
        "decoder": decoded.get("name", decoded.get("decoder")),
        "rule": matched.get("id", matched.get("Rule id")),
        "level": matched.get("level", matched.get("Level")),
        "description": matched.get("description", matched.get("Description")),
    }
    return [
        f"{case['name']}: {key}: oczekiwano {value!r}, otrzymano {actual.get(key)!r}"
        for key, value in expected.items()
        if actual.get(key) != value
    ]


def main():
    cases = json.loads((ROOT / "tests/cases.json").read_text(encoding="utf-8"))
    cases.extend(correlation_cases())
    result = subprocess.run(
        [
            "docker", "run", "--rm", "-i", "--network", "none",
            "--entrypoint", "/bin/bash",
            "--mount", f"type=bind,src={ROOT},dst=/integration,readonly",
            IMAGE, "/integration/tests/container.sh",
        ],
        input="\n".join(case["log"] for case in cases) + "\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
    if result.returncode:
        print(result.stdout, file=sys.stderr)
        return result.returncode

    output = ANSI_ESCAPE.sub("", result.stdout)
    phases = PHASE.split(output)
    events = []
    for phase, section in zip(phases[1::2], phases[2::2]):
        if phase == "1":
            events.append({})
        events[-1][phase] = section
    if len(cases) != len(events):
        print(output[:4000], file=sys.stderr)
        print(f"Oczekiwano {len(cases)} zdarzeń, przetworzono {len(events)}.", file=sys.stderr)
        return 1

    failures = []
    for case, sections in zip(cases, events):
        failures.extend(check_event(case, sections))
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1

    print(f"Wazuh {IMAGE.rsplit(':', 1)[1]}: zaliczono {len(cases)} zdarzeń.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
