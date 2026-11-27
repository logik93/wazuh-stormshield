#!/usr/bin/env python3
"""Allow a QNAP NAS on an existing Wazuh syslog listener."""

import fcntl
import ipaddress
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


MANAGER = Path("/var/ossec")
OSSEC_CONF = MANAGER / "etc/ossec.conf"
WAZUH = "wazuh-manager.service"
REMOTE = re.compile(r"<!--.*?-->|<remote\s*>.*?</remote\s*>", re.DOTALL)


def run(*command):
    subprocess.run(command, check=True)


def ask(label, default=""):
    suffix = f" [{default}]" if default else ""
    return input(f"{label}{suffix}: ").strip() or default


def syslog_listeners(text):
    for match in REMOTE.finditer(text):
        if match[0].startswith("<!--"):
            continue
        block = ET.fromstring(match[0])
        if block.findtext("connection", "").strip() == "syslog":
            yield match, block


def is_listed(nas, block, tag):
    for entry in block.findall(tag):
        try:
            network = ipaddress.ip_network((entry.text or "").strip(), strict=False)
        except ValueError:
            continue
        if nas in network:
            return True
    return False


def allow_nas(text, match, block, nas):
    if is_listed(nas, block, "denied-ips"):
        raise ValueError(f"Adres {nas} jest objęty denied-ips w wybranym nasłuchu.")
    if is_listed(nas, block, "allowed-ips"):
        return text

    closing = re.search(r"</remote\s*>$", match[0])
    line_start = match[0].rfind("\n", 0, closing.start()) + 1
    indent = match[0][line_start:closing.start()]
    if not indent.strip():
        offset = match.start() + line_start
        addition = f"{indent}  <allowed-ips>{nas}</allowed-ips>\n"
    else:
        offset = match.start() + closing.start()
        addition = f"<allowed-ips>{nas}</allowed-ips>"
    return text[:offset] + addition + text[offset:]


def listener_details(block):
    return (
        block.findtext("local_ip", "").strip(),
        block.findtext("protocol", "tcp").strip().upper(),
        int(block.findtext("port", "514")),
    )


def receiver_address(nas, bind, port):
    if bind and not ipaddress.ip_address(bind).is_unspecified:
        return bind
    family = socket.AF_INET6 if nas.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as client:
            client.connect((str(nas), port))
            return client.getsockname()[0]
    except OSError:
        return "adres IP managera Wazuh"


def write_config(path, text):
    current = path.stat()
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(text)
            file.flush()
            os.fchown(file.fileno(), current.st_uid, current.st_gid)
            os.fchmod(file.fileno(), stat.S_IMODE(current.st_mode))
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def apply(original, updated):
    if updated == original:
        print("Adres NAS-a jest już dozwolony na tym nasłuchu.")
        return

    directory = Path(tempfile.mkdtemp(prefix="wazuh-qnap-syslog-backup.", dir=MANAGER))
    backup = directory / OSSEC_CONF.name
    shutil.copy2(OSSEC_CONF, backup)
    restart_attempted = False
    try:
        write_config(OSSEC_CONF, updated)
        run(str(MANAGER / "bin/wazuh-remoted"), "-t")
        run(str(MANAGER / "bin/wazuh-analysisd"), "-t")
        restart_attempted = True
        run("systemctl", "restart", WAZUH)
        run("systemctl", "is-active", "--quiet", WAZUH)
    except BaseException:
        print("Przywracam konfigurację Wazuh sprzed zmiany.", file=sys.stderr)
        try:
            write_config(OSSEC_CONF, backup.read_text())
            if restart_attempted:
                subprocess.run(["systemctl", "restart", WAZUH], check=False)
        finally:
            print(f"Kopia: {backup}", file=sys.stderr)
        raise
    print(f"Kopia przed zmianą: {backup}")


def main():
    if os.geteuid() != 0:
        raise ValueError("Uruchom kreator przez sudo.")
    required = ("etc/rules/qnap_qulog_rules.xml", "etc/decoders/qnap_qulog_decoders.xml")
    if not all((MANAGER / path).is_file() for path in required):
        raise ValueError("Uruchom sudo ./install.sh i wybierz moduł QNAP.")
    if OSSEC_CONF.is_symlink() or not OSSEC_CONF.is_file():
        raise ValueError(f"Oczekiwano zwykłego pliku: {OSSEC_CONF}.")

    lock = MANAGER / ".wazuh-network-integrations.lock"
    with lock.open("a") as fd:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original = OSSEC_CONF.read_text()
        listeners = list(syslog_listeners(original))
        if not listeners:
            raise ValueError("W ossec.conf brakuje istniejącego nasłuchu syslog Wazuh. Zobacz docs/instalacja.md.")

        print("\nQNAP QuLog · Wspólny nasłuch sysloga Wazuh")
        for index, (_, block) in enumerate(listeners, 1):
            bind, protocol, port = listener_details(block)
            print(f"{index}) {protocol}/{port} na {bind or '*'}")
        selected = int(ask("Wybierz numer nasłuchu Stormshield", "1") if len(listeners) > 1 else "1")
        if not 1 <= selected <= len(listeners):
            raise ValueError("Podaj numer nasłuchu z listy.")
        match, block = listeners[selected - 1]
        bind, protocol, port = listener_details(block)
        nas = ipaddress.ip_address(ask("Adres IP QNAP-a widoczny dla managera"))
        if nas.is_unspecified or nas.is_multicast or "%" in str(nas):
            raise ValueError("Podaj adres unicast NAS-a bez nazwy interfejsu.")
        if bind and ipaddress.ip_address(bind).version != nas.version:
            raise ValueError("Adres QNAP-a i adres nasłuchu muszą używać tej samej wersji IP.")

        updated = allow_nas(original, match, block, nas)
        if updated != original:
            print(f"Dodam {nas} do allowed-ips nasłuchu {protocol}/{port} i zrestartuję Wazuh.")
            if ask("Zastosować ustawienia? (t/N)", "N").lower() not in ("t", "tak"):
                print("Anulowano.")
                return
        apply(original, updated)

        print("\nW QuLog Center → Log Sender ustaw ten sam cel co na Stormshieldzie:")
        print(f"  Odbiornik: {receiver_address(nas, bind, port)}")
        print(f"  Transport: {protocol}    Port: {port}")
        print("  Włącz logi zdarzeń i dostępu. Dopuść ruch z adresu NAS-a w zaporze managera.")


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print("\nKonfiguracja przerwana.", file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, ET.ParseError, subprocess.CalledProcessError) as error:
        print(f"Błąd konfiguracji QNAP: {error}", file=sys.stderr)
        sys.exit(1)
