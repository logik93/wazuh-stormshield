#!/usr/bin/env python3
"""Configure QNAP QuLog syslog reception on a Linux Wazuh manager."""

import fcntl
import ipaddress
import os
from pathlib import Path
import pwd
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
RSYSLOG_CONF = Path("/etc/rsyslog.d/35-wazuh-qnap.conf")
LOG_FILE = "/var/log/wazuh-qnap.log"
WAZUH = "wazuh-manager.service"
RSYSLOG = "rsyslog.service"

MODULE = re.compile(r"""(?im)^\s*\$ModLoad\s+imudp\b|module\s*\(\s*load\s*=\s*["']imudp["']""")
LOCALFILE = f"""<!-- QNAP QuLog: konfiguracja z kreatora wazuh-stormshield -->
<ossec_config>
  <localfile>
    <location>{LOG_FILE}</location>
    <log_format>syslog</log_format>
    <only-future-events>no</only-future-events>
  </localfile>
</ossec_config>
"""


def run(*command):
    subprocess.run(command, check=True)


def ask(label, default=""):
    suffix = f" [{default}]" if default else ""
    return input(f"{label}{suffix}: ").strip() or default


def write_config(path, text):
    current = path.stat() if path.exists() else None
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(text)
            file.flush()
            if current:
                os.fchown(file.fileno(), current.st_uid, current.st_gid)
            os.fchmod(file.fileno(), stat.S_IMODE(current.st_mode) if current else 0o644)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def wazuh_config(text):
    body = re.sub(r"^\s*<\?xml\s[^?]*\?>", "", text, count=1)
    roots = ET.fromstring(f"<config>{body}</config>")
    for localfile in roots.findall("ossec_config/localfile"):
        if localfile.findtext("location", "").strip() == LOG_FILE:
            if localfile.findtext("log_format", "").strip() != "syslog":
                raise ValueError(f"{LOG_FILE} ma już inny format w ossec.conf.")
            return text
    return text.rstrip() + "\n\n" + LOCALFILE


def rsyslog_sources():
    paths = [Path("/etc/rsyslog.conf"), *RSYSLOG_CONF.parent.glob("*.conf")]
    return "\n".join(
        line for path in paths if path != RSYSLOG_CONF and path.is_file()
        for line in path.read_text().splitlines() if not line.lstrip().startswith("#")
    )


def ensure_logfile():
    path = Path(LOG_FILE)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"Oczekiwano zwykłego pliku: {path}.")
    if path.exists():
        return False

    configured = re.search(r"(?im)^\s*\$PrivDropToUser\s+(\S+)", rsyslog_sources())
    user = configured[1] if configured else subprocess.check_output(
        ["systemctl", "show", "--property=User", "--value", RSYSLOG], text=True,
    ).strip()
    if not user:
        user = "root"
    account = pwd.getpwnam(user)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        os.fchown(descriptor, account.pw_uid, account.pw_gid)
        os.fchmod(descriptor, 0o640)
    except OSError:
        path.unlink()
        raise
    finally:
        os.close(descriptor)
    return True


def rsyslog_config(nas, port):
    load = "" if MODULE.search(rsyslog_sources()) else 'module(load="imudp")\n\n'
    return f"""# QNAP QuLog: konfiguracja z kreatora wazuh-stormshield
# qnap-address: {nas}
# qnap-port: {port}
{load}template(name="WazuhQnapLine" type="string"
  string="%timegenerated:::date-rfc3164% %hostname% qnap-qulog: %msg:::drop-last-lf%\\n")

ruleset(name="WazuhQnap") {{
  if $fromhost-ip == "{nas}" then {{
    action(type="omfile" file="{LOG_FILE}"
      fileCreateMode="0640" template="WazuhQnapLine")
  }}
}}

input(type="imudp" port="{port}" ruleset="WazuhQnap")
"""


def suggested_receiver(nas):
    family = socket.AF_INET6 if nas.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as client:
            client.connect((str(nas), 5515))
            return client.getsockname()[0]
    except OSError:
        return "adres IP hosta Wazuh/rsyslog"


def find_rsyslogd():
    executable = shutil.which("rsyslogd")
    if executable:
        return executable
    for directory in ("/usr/sbin", "/sbin", "/usr/local/sbin"):
        path = Path(directory) / "rsyslogd"
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def configure(configs, rsyslogd):
    changed = {path: text for path, text in configs.items()
               if not path.exists() or path.read_text() != text}
    if not changed:
        print("Ustawienia odbiornika są już zapisane.")
        return

    backup = Path(tempfile.mkdtemp(prefix="wazuh-qnap-syslog-backup.", dir=MANAGER))
    for path in changed:
        if path.exists():
            shutil.copy2(path, backup / path.name)

    restarted = []
    created_log = False
    try:
        for path, text in changed.items():
            write_config(path, text)
        run(rsyslogd, "-N1")
        run(str(MANAGER / "bin/wazuh-analysisd"), "-t")
        run(str(MANAGER / "bin/wazuh-logcollector"), "-t")
        created_log = ensure_logfile()
        for service in (RSYSLOG, WAZUH):
            restarted.append(service)
            run("systemctl", "restart", service)
            run("systemctl", "is-active", "--quiet", service)
    except BaseException:
        print("Przywracam pliki sprzed konfiguracji.", file=sys.stderr)
        for path in changed:
            previous = backup / path.name
            try:
                if previous.exists():
                    write_config(path, previous.read_text())
                else:
                    path.unlink(missing_ok=True)
            except OSError as error:
                print(f"Sprawdź {path}: {error}", file=sys.stderr)
        if created_log:
            try:
                log = Path(LOG_FILE)
                if log.stat().st_size == 0:
                    log.unlink()
            except OSError as error:
                print(f"Sprawdź {LOG_FILE}: {error}", file=sys.stderr)
        for service in restarted:
            subprocess.run(["systemctl", "restart", service], check=False)
        print(f"Kopia: {backup}", file=sys.stderr)
        raise
    print(f"Kopia ustawień sprzed zmiany: {backup}")


def metadata(text, key, fallback):
    match = re.search(rf"(?m)^# qnap-{key}: (\S+)$", text)
    return match[1] if match else fallback


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


def main():
    if os.geteuid() != 0:
        raise ValueError("Uruchom kreator przez sudo.")
    required = ("etc/rules/qnap_qulog_rules.xml", "etc/decoders/qnap_qulog_decoders.xml")
    if not all((MANAGER / path).is_file() for path in required):
        raise ValueError("Uruchom sudo ./install.sh i wybierz moduł QNAP.")
    for path in (OSSEC_CONF, RSYSLOG_CONF):
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError(f"Oczekiwano zwykłego pliku: {path}.")

    lock = MANAGER / ".wazuh-network-integrations.lock"
    with lock.open("a") as fd:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = RSYSLOG_CONF.read_text() if RSYSLOG_CONF.exists() else ""
        print("\nQNAP QuLog · Odbiór sysloga")
        nas = ipaddress.ip_address(ask("Adres IP NAS-a widoczny z odbiornika", metadata(previous, "address", "")))
        if nas.is_unspecified or nas.is_multicast or "%" in str(nas):
            raise ValueError("Podaj adres unicast NAS-a bez nazwy interfejsu.")
        port = int(ask("Lokalny port UDP", metadata(previous, "port", "5515")), 10)
        if not 1 <= port <= 65535:
            raise ValueError("Port musi mieścić się w zakresie 1–65535.")
        previous_port = re.search(r'input\s*\(\s*type="imudp"\s+port="(\d+)"\s+ruleset="WazuhQnap"', previous)
        if not previous_port or int(previous_port[1]) != port:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("0.0.0.0", port))

        ossec = wazuh_config(OSSEC_CONF.read_text())
        rsyslogd = find_rsyslogd()
        install_rsyslog = rsyslogd is None
        if install_rsyslog and not shutil.which("apt-get"):
            raise ValueError("Zainstaluj rsyslog za pomocą menedżera pakietów tej dystrybucji.")
        print(f"Z {nas} przez UDP/{port} → {LOG_FILE} → Wazuh.")
        if install_rsyslog:
            print("Kreator doinstaluje rsyslog przez apt-get.")
        if previous and not previous.startswith("# QNAP QuLog: konfiguracja z kreatora"):
            print(f"Istniejący {RSYSLOG_CONF} zostanie zapisany w kopii i zastąpiony.")
        if ask("Zastosować ustawienia? (t/N)", "N").lower() not in ("t", "tak"):
            print("Anulowano.")
            return
        if install_rsyslog:
            run("apt-get", "install", "-y", "rsyslog")
            rsyslogd = find_rsyslogd()
            if rsyslogd is None:
                raise ValueError("Pakiet rsyslog zainstalowano, ale nie znaleziono programu rsyslogd.")
        configure({OSSEC_CONF: ossec, RSYSLOG_CONF: rsyslog_config(nas, port)}, rsyslogd)

        print("\nW QuLog Center → Log Sender dodaj cel syslog:")
        print(f"  Odbiornik: {suggested_receiver(nas)}")
        print(f"  Transport: UDP    Port: {port}")
        print("  Włącz logi zdarzeń i dostępu. Dopuść ten port z adresu NAS-a w zaporze hosta.")
        print(f"  Pierwszy wpis sprawdzisz w {LOG_FILE}.")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print("\nKonfiguracja przerwana.", file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, KeyError, ET.ParseError, subprocess.CalledProcessError) as error:
        print(f"Błąd konfiguracji QNAP: {error}", file=sys.stderr)
        sys.exit(1)
