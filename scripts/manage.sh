#!/usr/bin/env bash
set -euo pipefail
shopt -s globstar nullglob

action=$1
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
manager=/var/ossec
service=wazuh-manager.service

fail() {
    printf 'Błąd: %s\n' "$*" >&2
    exit 1
}

(( EUID == 0 )) || fail "uruchom skrypt przez sudo."
[[ -x "$manager/bin/wazuh-analysisd" && -d "$manager/etc/decoders" && -d "$manager/etc/rules" ]] ||
    fail "oczekiwano instalacji managera w $manager."
command -v flock >/dev/null || fail "wymagany jest flock z pakietu util-linux."
if ! systemctl show --property=LoadState --value "$service" | grep -qx loaded; then
    fail "systemd nie udostępnia usługi $service."
fi

if [[ $action == install ]]; then
    printf 'Instalacja lub aktualizacja integracji Wazuh\n'
else
    printf 'Odinstalowanie integracji Wazuh\n'
fi
printf '1) Stormshield SNS\n2) MikroTik RouterOS\n3) Oba moduły\n0) Anuluj\n'
read -r -p 'Wybierz moduły [0–3]: ' choice || exit 0
case $choice in
    1) modules=(stormshield_sns) ;;
    2) modules=(mikrotik_routeros) ;;
    3) modules=(stormshield_sns mikrotik_routeros) ;;
    0|'') exit 0 ;;
    *) fail "wybierz opcję od 0 do 3." ;;
esac

umask 077
exec 9>"$manager/.wazuh-network-integrations.lock"
flock -n 9 || fail "inna instalacja lub dezinstalacja już trwa."

declare -a files=()
for module in "${modules[@]}"; do
    module_files=("decoders/${module}_decoders.xml" "rules/${module}_rules.xml")
    for file in "${module_files[@]}"; do
        target="$manager/etc/$file"
        [[ ! -L "$target" && ( ! -e "$target" || -f "$target" ) ]] ||
            fail "oczekiwano zwykłego pliku lub wolnej ścieżki: $target"
        if [[ $action == install ]]; then
            [[ -f "$project/$file" ]] || fail "brakuje pliku $project/$file."
            files+=("$file")
        elif [[ -f "$target" ]]; then
            files+=("$file")
        fi
    done
done

if (( ${#files[@]} == 0 )); then
    printf 'Wybrane moduły są już odinstalowane.\n'
    exit 0
fi

if [[ $action == install ]]; then
    for module in "${modules[@]}"; do
        if [[ $module == stormshield_sns ]]; then
            ids='11050[0-9]'
            if grep -lE 'name="stormshield"|<decoded_as>stormshield</decoded_as>' \
                /dev/null "$manager/etc/"{decoders,rules}/**/*.xml; then
                fail "znaleziono wcześniejszą integrację Stormshield. Zobacz docs/instalacja.md."
            fi
        else
            ids='11052[0-3]'
        fi
        for file in "$manager/etc/rules"/**/*.xml "$manager/ruleset/rules"/**/*.xml; do
            [[ $file != "$manager/etc/rules/${module}_rules.xml" ]] || continue
            if grep -qE "id=\"($ids)\"" "$file"; then
                fail "konflikt identyfikatorów reguł w $file."
            fi
        done
    done
fi

printf '\nPliki objęte operacją:\n'
printf "  $manager/etc/%s\n" "${files[@]}"
printf '\nSkrypt sprawdzi konfigurację i zrestartuje usługę %s.\n' "$service"
read -r -p 'Kontynuować? [t/N]: ' answer || exit 0
case $answer in
    t|T|tak|TAK) ;;
    *) printf 'Anulowano.\n'; exit 0 ;;
esac

backup=$(mktemp -d "$manager/wazuh-network-integrations-backup.XXXXXXXX")
mkdir -- "$backup/decoders" "$backup/rules"
for file in "${files[@]}"; do
    if [[ -f "$manager/etc/$file" ]]; then
        cp -a -- "$manager/etc/$file" "$backup/$file"
    fi
done

restart_attempted=false
restore_on_failure() {
    local status=$? file failed=0
    (( status != 0 )) || return 0
    trap '' INT TERM
    printf 'Operacja przerwana. Przywracam poprzednie pliki.\n' >&2
    for file in "${files[@]}"; do
        if [[ -f "$backup/$file" ]]; then
            cp -a -- "$backup/$file" "$manager/etc/$file" || failed=1
        else
            rm -f -- "$manager/etc/$file" || failed=1
        fi
    done
    if [[ $restart_attempted == true && $failed == 0 ]]; then
        systemctl restart "$service" && systemctl is-active --quiet "$service" || failed=1
    fi
    if (( failed )); then
        printf 'Automatyczne przywrócenie wymaga sprawdzenia.\n' >&2
    fi
    printf 'Kopia przed operacją: %s\n' "$backup" >&2
}
trap restore_on_failure EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for file in "${files[@]}"; do
    if [[ $action == install ]]; then
        install -o root -g wazuh -m 0640 -- "$project/$file" "$manager/etc/$file"
    else
        rm -f -- "$manager/etc/$file"
    fi
done

"$manager/bin/wazuh-analysisd" -t
restart_attempted=true
systemctl restart "$service"
systemctl is-active --quiet "$service"
trap - EXIT INT TERM
printf 'Gotowe. Kopia plików sprzed operacji: %s\n' "$backup"
