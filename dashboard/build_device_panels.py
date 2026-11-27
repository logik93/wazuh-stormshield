#!/usr/bin/env python3
"""Regenerate the panels that query optional fields without a data-view cache."""

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def search_url(rule, aggregation):
    return {
        "index": "wazuh-alerts-*",
        "body": {
            "size": 0,
            "query": {"bool": {
                "must": ["%dashboard_context-must_clause%"],
                "must_not": ["%dashboard_context-must_not_clause%"],
                "filter": [
                    "%dashboard_context-filter_clause%",
                    {"range": {"timestamp": {"%timefilter%": True}}},
                    {"term": {"rule.id": str(rule)}},
                ],
            }},
            "aggs": {"values": aggregation},
        },
    }


def text_mark(label, x, y, *, data=None, expression=False, name=None, **style):
    position = {
        "x": {"signal": x},
        "y": {"signal": y},
        "text": {"signal" if expression else "value": label},
        **{key: {"value": value} for key, value in style.items()},
    }
    mark = {"type": "text", "encode": {"update": position}}
    if data:
        mark["from"] = {"data": data}
    if name:
        mark["name"] = name
    return mark


def table_spec(url, columns, empty_message):
    page_size = 9
    header = "#20364b"
    text = "#24374a"
    previous = ("‹ Poprzednia", "prev_page", "12")
    following = ("Następna ›", "next_page", "max(12, width - 95)")
    spec = {
        "$schema": "https://vega.github.io/schema/vega/v5.json",
        "autosize": {"type": "fit-x", "contains": "padding"},
        "height": 268,
        "padding": 4,
        "config": {"kibana": {"renderer": "svg"}},
        "data": [
            {"name": "values", "url": url, "format": {"property": "aggregations.values.buckets"},
             "transform": [{"type": "window", "ops": ["row_number"], "as": ["row"]}]},
            {"name": "visible", "source": "values", "transform": [{
                "type": "filter",
                "expr": f"datum.row > page * {page_size} && datum.row <= (page + 1) * {page_size}",
            }]},
        ],
        "signals": [
            {"name": "pages", "update": f"max(1, ceil(length(data('values')) / {page_size}))"},
            {"name": "page", "value": 0, "on": [
                {"events": "@prev_page:click", "update": "max(0, page - 1)"},
                {"events": "@next_page:click", "update": "min(pages - 1, page + 1)"},
            ]},
        ],
        "marks": [
            {"type": "rect", "encode": {"update": {
                "x": {"value": 0}, "width": {"signal": "width"},
                "y": {"value": 0}, "height": {"value": 28}, "fill": {"value": "#e9f1f8"},
            }}},
            {"type": "rect", "from": {"data": "visible"}, "encode": {"update": {
                "x": {"value": 0}, "width": {"signal": "width"},
                "y": {"signal": f"28 + (datum.row - 1 - page * {page_size}) * 23"},
                "height": {"value": 23}, "fill": {"signal": "datum.row % 2 ? '#ffffff' : '#f2f6fa'"},
            }}},
            text_mark(empty_message, "12", "56", fill=text, fontSize=13),
        ],
    }
    spec["marks"][-1]["encode"]["update"]["opacity"] = {"signal": "length(data('values')) ? 0 : 1"}
    for label, field, start, ratio in columns:
        x = f"12 + width * {start}"
        spec["marks"].append(text_mark(label, x, "19", fill=header, fontWeight="bold", fontSize=12))
        row = text_mark(
            f"datum.{field}", x, f"44 + (datum.row - 1 - page * {page_size}) * 23",
            data="visible", expression=True, fill=text, fontSize=13,
        )
        row["encode"]["update"]["limit"] = {"signal": f"max(0, width * {ratio} - 14)"}
        row["encode"]["update"]["tooltip"] = {"signal": f"datum.{field}"}
        spec["marks"].append(row)
    for label, name, x in (previous, following):
        mark = text_mark(label, x, "256", name=name, fill="#24659c", cursor="pointer", fontSize=12)
        mark["encode"]["update"]["opacity"] = {"signal": "pages > 1 ? 1 : 0"}
        spec["marks"].append(mark)
    page_label = text_mark(
        "'Strona ' + (page + 1) + ' / ' + pages", "width / 2", "256", expression=True,
        align="center", fill=text, fontSize=12,
    )
    page_label["encode"]["update"]["opacity"] = {"signal": "pages > 1 ? 1 : 0"}
    spec["marks"].append(page_label)
    return spec


def qnap_capacity():
    fields = ("free", "total", "free_percent", "measured_at")
    aggregation = {
        "terms": {"field": "data.qnap_capacity.volume", "size": 100, "order": {"_key": "asc"}},
        "aggs": {"latest": {"top_hits": {
            "size": 1, "sort": [{"timestamp": {"order": "desc"}}],
            "_source": {"includes": ["data.qnap_capacity." + name for name in fields]},
        }}},
    }
    spec = table_spec(
        search_url(110547, aggregation),
        [
            ("NAS / wolumin", "key", 0, .30),
            ("Wolne miejsce", "free", .30, .17),
            ("Pojemność", "total", .47, .17),
            ("Wolne (%)", "free_percent", .64, .13),
            ("Pomiar (UTC)", "measured_at", .77, .23),
        ],
        "Brak pomiarów w wybranym okresie. Sprawdź kolektor SNMP i alerty 110547.",
    )
    for name in fields:
        spec["data"][0]["transform"].append({
            "type": "formula",
            "as": name,
            "expr": f"datum.latest.hits.hits[0]._source.data.qnap_capacity.{name} || '—'",
        })
    return spec


def mikrotik_table(rule, field, heading, empty_message):
    return table_spec(
        search_url(rule, {"terms": {"field": "data.routeros." + field, "size": 10}}),
        [(heading, "key", 0, .68), ("Alerty", "doc_count", .68, .32)],
        empty_message,
    )


def update_file(filename, specs, *, check):
    path = ROOT / filename
    lines = path.read_text().splitlines()
    updated = set()
    for index, line in enumerate(lines):
        obj = json.loads(line)
        if obj["id"] not in specs:
            continue
        attrs = obj["attributes"]
        previous = json.loads(attrs["visState"])
        attrs["visState"] = compact({
            "title": previous["title"], "type": "vega", "aggs": [],
            "params": {"spec": compact(specs[obj["id"]])},
        })
        attrs["kibanaSavedObjectMeta"]["searchSourceJSON"] = compact({
            "query": {"language": "kuery", "query": ""}, "filter": [],
        })
        obj["references"] = []
        updated.add(obj["id"])
        lines[index] = compact(obj)
    if updated != specs.keys():
        raise SystemExit(f"{filename}: brakuje paneli {specs.keys() - updated}")
    content = "\n".join(lines) + "\n"
    if check:
        if content != path.read_text():
            raise SystemExit(f"{filename}: najpierw wygeneruj plik ponownie.")
    else:
        path.write_text(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    update_file("qnap-qulog.ndjson", {"logik93-qnap-qulog-volume-capacity": qnap_capacity()}, check=args.check)
    update_file("mikrotik-routeros.ndjson", {
        "logik93-mikrotik-routeros-interfaces": mikrotik_table(
            110521, "input_interface", "Interfejs", "Brak blokad z odczytanym interfejsem wejściowym.",
        ),
        "logik93-mikrotik-routeros-login-methods": mikrotik_table(
            110522, "auth_method", "Metoda logowania", "Brak błędów logowania z zapisaną metodą.",
        ),
        "logik93-mikrotik-routeros-dhcp-clients": mikrotik_table(
            110523, "client_hostname", "Klient DHCP", "Brak przydziałów z zapisaną nazwą klienta.",
        ),
    }, check=args.check)


if __name__ == "__main__":
    main()
