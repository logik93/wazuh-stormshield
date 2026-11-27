# QNAP QuLog Center

Moduł analizuje anglojęzyczne komunikaty tekstowe przesłane przez syslog. Obejmuje logowania i zmiany plików SMB, błędy dysków i RAID, kopie, migawki, replikację oraz wybrane awarie sprzętu i zasilania. Dashboard pokazuje alerty zapisane przez Wazuh. Harmonogram i stan ostatniej kopii nadal można sprawdzić w aplikacji kopii zapasowych na NAS-ie.

## Szybkie wdrożenie na wspólnym nasłuchu Wazuh

Potrzebujesz managera Wazuh z istniejącym nasłuchem `<remote>` o typie `syslog`, np. tym, z którego korzysta Stormshield. Na hoście managera:

```bash
sudo ./install.sh
```

1. Wybierz **4) QNAP QuLog Center** i potwierdź instalację.
2. Gdy instalator zapyta o odbiór sysloga, naciśnij Enter. Jeśli manager ma kilka nasłuchów syslog, wybierz nasłuch Stormshielda. Podaj adres IP, z którego QNAP wysyła logi.
3. Po potwierdzeniu kreator dopisze adres QNAP-a do istniejących wpisów `allowed-ips`, sprawdzi konfigurację i zrestartuje managera. W razie błędu przywróci kopię `ossec.conf`.
4. W **QuLog Center → Log Sender** na QNAP-ie ustaw ten sam adres, port i transport co na Stormshieldzie. Wybierz logi zdarzeń i dostępu. Jeśli host ma zaporę, dopuść ruch z adresu NAS-a na używany port.
5. Przejdź do [weryfikacji alertów](#sprawdzenie-logów-i-dashboardu).

Jeśli moduł jest już zainstalowany i zaktualizowany, możesz uruchomić kreator osobno:

```bash
sudo ./configure-qnap.sh
```

Przy ręcznej konfiguracji można dopisać ten sam wpis `<allowed-ips>ADRES_QNAP</allowed-ips>` bezpośrednio do bloku syslog używanego przez Stormshield. [Konfiguracja nasłuchu syslog Wazuh](instalacja.md#2-włącz-odbiór-sysloga)

## Opcjonalny przekaźnik rsyslog

Jeśli istniejąca instalacja korzysta z przekaźnika, dekoder obsługuje także znacznik `qnap-qulog`. Przekaźnik można zastosować do komunikatów QNAP bez rozpoznawalnego nagłówka. W QTS lub QuTS hero otwórz **QuLog Center → Log Sender** i dodaj cel syslog. Wybierz logi zdarzeń i dostępu, jeśli są dostępne dla danego firmware. W przykładzie serwer rsyslog działa na hoście managera Wazuh. Skonfiguruj NAS do wysyłania na jego adres przez **UDP 5515**. Ogranicz ten port do adresów NAS-ów w sieci zarządzającej.

Poniżej przykładowy plik `/etc/rsyslog.d/35-wazuh-qnap.conf`. Podmień `192.0.2.50` na rzeczywisty adres NAS-a widoczny dla odbiornika. Jeśli masz już załadowany `imudp`, pomiń pierwszą linię. Wybierz wolny port i ustaw go także na NAS-ie. Konfiguracja zapisuje osobny plik i dodaje znacznik `qnap-qulog`, którego dekoder używa do rozpoznawania komunikatów.

```rsyslog
module(load="imudp")

template(name="WazuhQnapLine" type="string"
  string="%timegenerated:::date-rfc3164% %hostname% qnap-qulog: %msg:::drop-last-lf%\n")

ruleset(name="WazuhQnap") {
  if $fromhost-ip == "192.0.2.50" then {
    action(type="omfile" file="/var/log/wazuh-qnap.log"
      fileCreateMode="0640" template="WazuhQnapLine")
  }
}

input(type="imudp" port="5515" ruleset="WazuhQnap")
```

Sprawdź składnię i po udanej walidacji zrestartuj rsyslog.

```bash
sudo rsyslogd -N1 &&
sudo systemctl restart rsyslog
```

Poczekaj, aż w `/var/log/wazuh-qnap.log` pojawi się nowy wpis. Dodaj do istniejącego bloku `<ossec_config>` w `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <location>/var/log/wazuh-qnap.log</location>
  <log_format>syslog</log_format>
</localfile>
```

Sprawdź konfigurację i zrestartuj Wazuh:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t &&
sudo /var/ossec/bin/wazuh-logcollector -t &&
sudo systemctl restart wazuh-manager
```

Dodaj ten plik do lokalnej rotacji logów rsyslog. Jeżeli rsyslog działa na oddzielnym hoście, ten sam blok `localfile` może czytać lokalny agent Wazuh na przekaźniku.

## Sprawdzenie logów i dashboardu

1. Wklej pełną linię sysloga do `sudo /var/ossec/bin/wazuh-logtest`. W fazie 2 oczekuj dekodera `qnap-qulog`. W fazie 3 komunikat pasujący do jednej z reguł otrzyma jedno z ID `110541–110546`, `110548` lub `110549`. Zdarzenie ogólne otrzyma poziom 0.
2. W **Discover** wybierz zakres obejmujący nowe alerty i filtr `rule.groups: "qnap" AND rule.groups: "qulog"`. Jeśli nie widzisz wpisów, sprawdź rzeczywisty adres źródłowy, port, transport, listę `allowed-ips`, próg `log_alert_level` i zapis alertów w managerze.
3. Zaimportuj [dashboard QNAP QuLog · Ochrona danych i dostęp](../dashboard/qnap-qulog.ndjson). Plik zawiera 17 obiektów. W tabeli **Źródła sysloga** sprawdź adres NAS-a w polu `location`. [Instrukcja importu](../dashboard/README.md)

| ID reguły | Co pojawi się w dashboardzie |
| --- | --- |
| `110541`, `110542` | Błędy i sukcesy logowania |
| `110543` | Problemy z dyskami, RAID lub woluminem |
| `110544`, `110545` | Wynik kopii zapasowej, replikacji lub migawki |
| `110546` | Przegrzanie, awarie sprzętu lub zasilania |
| `110548` | Dodanie, zapis, zmiana nazwy lub przeniesienie przez SMB |
| `110549` | Usunięcie przez SMB |

Na syntetycznych komunikatach sprawdzono bezpośredni odbiór QNAP-a i Stormshielda na jednym porcie UDP w Wazuh 4.14.5. Osobno sprawdzono wariant z przekaźnikiem i `localfile`. Bezpośredni dekoder rozpoznaje nazwy programu QNAP, QTS, QuTS, QuLog, qulogd lub QuLogCenter albo początek komunikatu `[QuLog Center]`. Dashboard sprawdzono w przeglądarce z testowym indeksem alertów. Format, język i treść komunikatów różnią się zależnie od wersji QTS, QuTS hero i aplikacji. Jeśli log z konkretnego urządzenia pozostaje nierozpoznany albo trafia tylko do reguły `110540`, przyda się zanonimizowana oryginalna linia sysloga z nagłówkiem i wersją firmware.

### Logi dostępu SMB z `qulogd`

Komunikaty `conn log:` pokazują użytkownika, adres klienta, nazwę komputera, typ połączenia, ścieżkę zasobu i akcję. Dashboard pokazuje błędy logowania, dziennik zmian plików oraz licznik usunięć. `Read` pozostaje zdarzeniem poziomu 0, żeby zwykłe odczyty nie zapełniały indeksu alertów. Zdarzenia poziomu 0 można sprawdzić w archiwum Wazuh, jeśli archiwizacja jest włączona.

Jeśli NAS wysyła tylko logi dostępu, panele kopii, dysków i zasilania poczekają na odpowiednie logi systemowe. Aktualizacja dekodera zaczyna działać dla nowych komunikatów. Wcześniejsze wpisy z `archives.json` nie pojawią się samoczynnie na dashboardzie alertów.

## Źródła i inspiracje

- Zestaw monitorowania MikroTika łączy widoki urządzeń z osobnym przeglądem sysloga. Tu używamy filtrów alertów Wazuh oraz tabel blokad, logowań i DHCP. [MKTXP Stack](https://github.com/akpw/mktxp-stack#mikrotik-centralized-logging-configuration)
- Widoki Synology porządkują zdarzenia NAS-a według dostępu i operacji na danych. Ten pakiet dostosowuje te obszary do tekstowych komunikatów QNAP. [phastier/wazuh](https://github.com/phastier/wazuh#synology-dsm-nas)
- Integracja QNAP w Home Assistant rozdziela kondycję dysków, woluminów i samego urządzenia. Nasz dashboard pokazuje zarejestrowane alerty w tych obszarach. [Home Assistant · QNAP](https://github.com/home-assistant/core/tree/dev/homeassistant/components/qnap)
- QuLog Center zawiera konfigurację wysyłki logów do sysloga. Nazewnictwo opcji zależy od wersji systemu. [Dokumentacja QTS](https://docs.qnap.com/operating-system/qts/5.2.x/en-us/)

## Wolne miejsce na woluminach

Panel **Wolne miejsce na woluminach** pokazuje ostatni odczyt każdego woluminu w wybranym okresie. Są w nim wolne miejsce, pojemność, procent wolnego i moment odczytu w UTC. Gdy w wybranym okresie nie ma pomiarów, panel wyświetla komunikat. Sprawdź działanie kolektora i obecność alertu `110547` w indeksie. Dane dotyczą woluminów udostępnionych przez NAS-MIB, a pojemność puli może się różnić, zwłaszcza przy woluminach thin.

### 1. Udostępnij pomiary przez SNMPv3

Włącz SNMPv3 w ustawieniach NAS-a i skonfiguruj odczyt z uwierzytelnieniem i szyfrowaniem (`authPriv`). Ogranicz dostęp UDP 161 do adresu hosta zbierającego pomiary. Na tym hoście zainstaluj Python 3 i Net-SNMP z poleceniem `snmpwalk` (pakiet `snmp` na Debianie i Ubuntu). Kolektor używa liczników bajtowych z tabeli woluminów QNAP i sprawdza starszą tabelę bajtową, jeśli nowa nie dostarcza danych. [Definicje NAS-MIB](https://github.com/librenms/librenms/blob/master/mibs/qnap/NAS-MIB)

Zapisz ustawienia SNMPv3 w prywatnym katalogu. Przykład dla harmonogramu użytkownika root wykorzystuje katalog `/root/.snmp-qnap` z prawami `0700` i plik `snmp.conf` z prawami `0600`. W pliku skonfiguruj opcje Net-SNMP `defSecurityName`, `defAuthType`, `defPrivType`, `defAuthPassphrase` i `defPrivPassphrase` zgodnie z ustawieniami NAS-a. Hasła wpisz bezpośrednio do tego pliku. Dla osobnych poświadczeń użyj osobnego katalogu na NAS. [Opcje snmp.conf](https://github.com/net-snmp/net-snmp/blob/master/man/snmp.conf.5.def)

Z katalogu repozytorium uruchom próbny odczyt. Podmień adres i nazwę przykładową. Wynik powinien zawierać jeden obiekt JSON na wolumin.

```bash
sudo python3 scripts/qnap-volumes.py 192.0.2.50 \
  --device NAS1 --snmp-config-dir /root/.snmp-qnap
```

### 2. Zapisuj odczyty i przekaż je do Wazuh

Zaktualizuj moduł QNAP przez `sudo ./install.sh` i wybierz **4) QNAP QuLog Center**. Następnie przygotuj plik odczytów, jeżeli jeszcze nie istnieje:

```bash
sudo sh -c 'umask 077; touch /var/log/wazuh-qnap-volumes.jsonl'
```

W `/var/ossec/etc/ossec.conf` dodaj w istniejącym `<ossec_config>`:

```xml
<localfile>
  <location>/var/log/wazuh-qnap-volumes.jsonl</location>
  <log_format>json</log_format>
</localfile>
```

Po kontroli przez `sudo /var/ossec/bin/wazuh-logcollector -t` zrestartuj managera. W crontabie użytkownika, który ma dostęp do konfiguracji SNMP i pliku wynikowego, dodaj np. poniższy wpis. Podstaw rzeczywistą ścieżkę do repozytorium. Dodaj ten plik do rotacji logów.

```cron
*/15 * * * * /usr/bin/python3 /opt/wazuh-stormshield/scripts/qnap-volumes.py 192.0.2.50 --device NAS1 --snmp-config-dir /root/.snmp-qnap >> /var/log/wazuh-qnap-volumes.jsonl
```

Zaimportuj opcjonalny [panel pojemności](../dashboard/qnap-volumes-snmp.ndjson) z opcją **Overwrite**. W trybie edycji dashboardu wybierz **Add from library** i dodaj **QNAP QuLog · Wolne miejsce na woluminach**. Przy pierwszym uruchomieniu ustaw okres obejmujący pomiar i potwierdź w **Discover**, że pojawiła się reguła `110547`. Pomiar ma poziom 3, więc indeksacja wymaga odpowiedniego progu `log_alert_level`. Dane o pojemności trafiają do panelu pojemności. Liczniki zdarzeń QuLog pozostają oparte na logach zdarzeń.
