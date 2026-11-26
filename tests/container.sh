#!/usr/bin/env bash
set -euo pipefail

cd /var/ossec

# Restore files normally populated by the official image's init process.
distribution_files=data_tmp/exclusion/var/ossec/etc
install -o root -g wazuh -m 0640 "$distribution_files/internal_options.conf" etc/
for list in malware-hashes malicious-ip malicious-domains; do
    install -o wazuh -g wazuh -m 0640 "$distribution_files/lists/malicious-ioc/$list" etc/lists/malicious-ioc/
done
printf '\nanalysisd.rlimit_nofile=1024\nwazuh_db.rlimit_nofile=1024\n' >> etc/local_internal_options.conf
install -o root -g wazuh -m 0640 /integration/decoders/*.xml etc/decoders/
install -o root -g wazuh -m 0640 /integration/rules/*.xml etc/rules/

bin/wazuh-analysisd -t
bin/wazuh-db
bin/wazuh-analysisd
for attempt in {1..100}; do
    if [[ -S queue/sockets/logtest ]]; then
        exec bin/wazuh-logtest
    fi
    sleep 0.1
done
tail -40 logs/ossec.log >&2
exit 1
