# Instalacja

Potrzebujesz managera Wazuh 4.x, dostępu administracyjnego do managera i możliwości wysyłania sysloga z urządzenia. Wersję używaną w testach znajdziesz w [dokumentacji](dekodery-i-reguly.md#testy).

Na hoście managera albo na stacji, z której skopiujesz pliki, pobierz projekt:

```bash
git clone https://github.com/logik93/wazuh-stormshield.git
cd wazuh-stormshield
```

### Przejście z istniejącej integracji Stormshield

Jeżeli Wazuh już generuje alerty Stormshield z dekodera `stormshield` lub z reguły `100301`, znajdź ich definicje przed instalacją:

```bash
sudo grep -REn 'name="stormshield"|id="100301"|<decoded_as>stormshield</decoded_as>' \
  /var/ossec/etc/decoders /var/ossec/etc/rules
```

Zachowaj kopię starego zestawu poza katalogami ładowanymi przez Wazuh. Jeżeli pliki należą wyłącznie do starej integracji, przenieś je do katalogu kopii. Jeżeli są współdzielone z innymi integracjami, usuń z aktywnych plików tylko stare definicje SNS i reguły, które od nich zależą. Następnie dodaj nowy zestaw w kroku 1. Jeżeli syslog z SNS już dociera, przejdź po instalacji plików bezpośrednio do sprawdzenia konfiguracji i restartu w kroku 2. Istniejący nasłuch i profil wysyłki na zaporze wystarczą.

## 1. Załaduj wybrane moduły

### Instalator interaktywny dla Linuksa

Skrypt wymaga Bash, systemd i `flock` z pakietu `util-linux`. Na hoście z managerem w `/var/ossec` uruchom:

```bash
sudo ./install.sh
```

Wybierz Stormshield SNS, MikroTik RouterOS, QNAP lub wszystkie moduły. Skrypt pokaże listę plików i poprosi o potwierdzenie przed ich zmianą. Sprawdzi konfigurację przez `wazuh-analysisd -t`, zrestartuje managera i sprawdzi stan usługi. Jeśli walidacja lub restart się nie powiedzie, skrypt odtworzy pliki sprzed operacji. Po zakończeniu wyświetli ścieżkę do kopii, jeśli operacja została rozpoczęta.

Jeśli syslog już działa, przejdź do kroku 4, a następnie zaimportuj dashboard. Dla nowego nasłuchu wykonaj kroki 2 i 3. Skrypt zarządza plikami reguł i dekoderów. Konfigurację odbioru sysloga i dashboard dodajesz osobno.

### Instalacja ręczna

Na hoście managera, z katalogu repozytorium, sprawdź czy zakresy `110500–110509`, `110520–110523` i `110540–110547` są wolne w Twoim zestawie reguł. Jeżeli inny pakiet rozpoznaje te same komunikaty, wybierz jeden zestaw dekoderów i odpowiadających mu reguł. Przy aktualizacji zachowaj kopie zastępowanych plików XML oraz kopię `/var/ossec/etc/ossec.conf`.

```bash
sudo grep -RE 'id="(11050[0-9]|11052[0-3]|11054[0-7])"' /var/ossec/etc/rules /var/ossec/ruleset/rules
```

Uruchom bloki dla wybranych urządzeń.

```bash
sudo install -o root -g wazuh -m 0640 decoders/stormshield_sns_decoders.xml /var/ossec/etc/decoders/
sudo install -o root -g wazuh -m 0640 rules/stormshield_sns_rules.xml /var/ossec/etc/rules/
```

```bash
sudo install -o root -g wazuh -m 0640 decoders/mikrotik_routeros_decoders.xml /var/ossec/etc/decoders/
sudo install -o root -g wazuh -m 0640 rules/mikrotik_routeros_rules.xml /var/ossec/etc/rules/
```

```bash
sudo install -o root -g wazuh -m 0640 decoders/qnap_qulog_decoders.xml /var/ossec/etc/decoders/
sudo install -o root -g wazuh -m 0640 rules/qnap_qulog_rules.xml /var/ossec/etc/rules/
```

Jeśli manager działa w kontenerze, umieść pliki w odpowiednich trwałych katalogach managera. W klastrze wprowadź zmiany zestawu reguł na węźle master i sprawdź ich synchronizację przed skierowaniem ruchu na węzły odbierające syslog.

## 2. Włącz odbiór sysloga

Jeśli instalujesz QNAP, użyj [dedykowanej konfiguracji rsyslog i localfile](qnap.md). Dla Stormshielda i MikroTika wykonaj poniższe kroki.

Wewnątrz istniejącego `<ossec_config>` w `/var/ossec/etc/ossec.conf` dodaj blok albo uzupełnij istniejący nasłuch sysloga na tym porcie. Podmień przykładowe adresy na adresy nadawców widoczne z managera. Dodaj tylko wpisy dla używanych nadawców.

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.0.2.10</allowed-ips>
  <allowed-ips>192.0.2.20</allowed-ips>
</remote>
```

Udostępnij port UDP wyłącznie z adresów nadawców w zaufanej sieci. Gdy potrzebujesz szyfrowania, użyj odbiornika syslog z TLS i przekaż wpisy do Wazuh przez lokalny plik `<localfile>` z formatem `syslog` lub do nasłuchu dostępnego jedynie z przekaźnika. Przekaźnik powinien zachować treść komunikatu, zwłaszcza klucze WELF i ich cudzysłowy. Dla kontenera skieruj port UDP na usługę managera.

Przed restartem sprawdź konfigurację.

```bash
sudo /var/ossec/bin/wazuh-analysisd -t &&
sudo /var/ossec/bin/wazuh-remoted -t &&
sudo systemctl restart wazuh-manager
```

## 3. Skonfiguruj nadawców

### Stormshield SNS

W panelu SNS przejdź do **Konfiguracja → Powiadomienia → Logi – Syslog – IPFIX → Syslog**. Nazwy sekcji mogą się różnić między wersjami. Dodaj profil ze wskazaniem managera lub przekaźnika, portu i transportu zgodnych z odbiornikiem. Wybierz natywny format WELF z polami `id=firewall` i `logtype=`. Włącz interesujące Cię rodziny, np. filtrowanie, alarmy, uwierzytelnianie, VPN i audyt administratora. Sprawdź też, czy wybrane reguły filtrowania na SNS mają włączone logowanie.

### MikroTik RouterOS 7

Utwórz akcję zdalnego logowania z BSD syslog. W przykładzie `192.0.2.30` to odbiornik i wymaga podmiany. Zaznacz `log=yes` oraz ustaw `log-prefix=WAZUH-DROP` wyłącznie na istniejących regułach z akcją drop/reject, których zdarzenia chcesz wysyłać. Na ruchliwej zaporze wybierz reguły o spodziewanym, akceptowalnym wolumenie logów.

```routeros
/system logging action add name=wazuh target=remote remote=192.0.2.30 remote-port=514 bsd-syslog=yes
/system logging add action=wazuh topics=firewall
/system logging add action=wazuh topics=account
/system logging add action=wazuh topics=system,error
/system logging add action=wazuh topics=dhcp,info
```

Tematy i szczegóły zdalnej akcji sprawdź w konfiguracji swojej wersji RouterOS. `WAZUH-DROP` musi wystąpić na początku treści po opcjonalnych tematach.

## 4. Sprawdź wdrożenie

1. Wklej jedną surową linię z urządzenia do `sudo /var/ossec/bin/wazuh-logtest`. W fazie 2 sprawdź dekoder i pola, a w fazie 3 oczekiwaną regułę. Przykładowe komunikaty do odtworzenia są w [zestawie testowym](../tests/cases.json).
2. Sprawdź zdarzenie z urządzenia na managerze, lokalnie w `/var/ossec/logs/alerts/alerts.json` albo w Wazuh Dashboard po `rule.groups:stormshield`, `rule.groups:mikrotik` lub `rule.groups:qnap`. Gdy faza 3 pokazuje poziom 0, wpis jest dekodowany bez alertu. Sprawdź ustawienie `log_alert_level`, jeżeli poziom reguły jest niższy niż próg managera.
3. Jeśli dekodowanie lokalne działa, a alert nie dociera po sieci, sprawdź transport, faktyczny adres źródłowy widziany przez managera, `allowed-ips`, port oraz komunikaty managera w `/var/ossec/logs/ossec.log`. Do sprawdzenia rzeczywistej treści zdarzeń użyj surowego logu z przekaźnika lub archiwum Wazuh, jeżeli jest już włączone.

## 5. Zaimportuj dashboard

Wybierz plik NDJSON dla swojego urządzenia i zaimportuj go przez **Dashboard Management → Saved Objects → Import**. Otwórz właściwy dashboard i wybierz okres obejmujący nowe alerty. [Pliki dashboardów i instrukcja importu](../dashboard/README.md)

## Wycofanie zmian

Jeśli używasz interaktywnego instalatora, uruchom `sudo ./uninstall.sh` i wybierz moduły do usunięcia. Skrypt usuwa ich pliki XML, waliduje konfigurację i restartuje managera. Poprzednie wersje plików znajdują się w katalogu kopii wskazanym po operacji. Jeśli przechodziłeś ze starszej integracji, przywróć jej pliki z osobnej kopii i ponownie sprawdź konfigurację przed restartem.

Przy instalacji ręcznej wykonaj poniższe kroki.

Usuń wyłącznie pliki dodane w kroku 1 albo przywróć ich poprzednie wersje. Jeżeli zmiana obejmowała nasłuch, przywróć właściwy blok `remote` z kopii. Sprawdź konfigurację i uruchom ponownie managera jak w kroku 2.
