# Dekodery i reguły

## Stormshield SNS

Dekoder rozpoznaje treść rozpoczynającą się od `id=firewall` lub `id="firewall"`. Wazuh może wcześniej zdjąć nagłówek BSD syslog. Każde pole jest wydobywane przez osobny dekoder siostrzany. Dzięki temu kolejność kluczy jest dowolna, opcjonalne pola mogą wypaść, a `src` i `dst` nie są mylone z adresami NAT ani z fragmentami cytowanego `msg`. Puste wartości są pomijane. Zapis sekwencji ucieczki w cytowanym tekście jest zachowywany.

| Dane w WELF | Pole widoczne w Wazuh |
| --- | --- |
| `src`, `dst`, `srcport`, `dstport` | `srcip`, `dstip`, `srcport`, `dstport` |
| `ipproto`, `proto` | `protocol`, `sns.application` |
| `fw`, `logtype`, `pri`, `time`, `tz` | `sns.device`, `sns.logtype`, `sns.priority`, `sns.time`, `sns.timezone` |
| `action`, `ruleid`, `rulename`, `srcifname`, `dstifname` | `sns.action`, `sns.policy_id`, `sns.policy_name`, `sns.source_interface`, `sns.destination_interface` |
| `modsrc`, `modsrcport`, `origdst`, `origdstport` | `sns.translated_source`, `sns.translated_source_port`, `sns.original_destination`, `sns.original_destination_port` |
| `user`, `domain`, `address`, `method`, `error`, `msg` | `srcuser`, `sns.domain`, `sns.management_ip`, `sns.auth_method`, `sns.error`, `sns.message` |
| `alarmid`, `class`, `risk`, `localnet`, `remotenet`, `service` | `sns.alarm_id`, `sns.alarm_class`, `sns.risk`, `sns.local_network`, `sns.remote_network`, `sns.service` |

| ID | Poziom | Dopasowanie |
| --- | ---: | --- |
| 110500 | 0 | Zdarzenie SNS bez pasującej reguły szczegółowej, m.in. dozwolony ruch, udane logowanie i telemetria |
| 110501 | 4 | Blokada w `filter`, `connection`, `web` lub `ssl`. Akcje `block`, `deny`, `drop`, `reject` bez rozróżniania wielkości liter |
| 110502 | 6 | Alarm urządzenia, także systemowy |
| 110503 | 9 | Alarm z blokadą i rozpoznaną klasą inną niż `system` |
| 110504 | 6 | Zdarzenie `auth` z dodatnim kodem `error` |
| 110505 | 6 | Komunikat `Authentication failed` bez jawnego kodu sukcesu |
| 110506 | 7 | `vpn` lub `xvpn` z pasującym angielskim komunikatem o błędzie |
| 110507 | 5 | Wybrane polecenia `CONFIG` w audycie `server` z kodem sukcesu |
| 110508 | 10 | 5 błędów uwierzytelnienia w 120 s z tego samego IP na tej samej zaporze |
| 110509 | 8 | 10 blokad ruchu w 60 s z tego samego IP na tej samej zaporze |

Poziom 0 umożliwia sprawdzenie dekodowania w `wazuh-logtest`. Jeśli potrzebujesz zachować także ruch dozwolony, skonfiguruj archiwizację Wazuh z retencją odpowiednią do wolumenu. W alertach JSON pola dynamiczne znajdziesz pod `data.sns`. Reguły oparte na komunikatach obejmują wskazane warianty angielskie. Korelację warto dostroić, gdy wiele klientów dzieli jeden adres NAT.

## Jak czytać identyfikator alarmu SNS

`alarmid` identyfikuje alarm w Stormshieldzie. Wazuh zachowuje go w `data.sns.alarm_id`, a tekst `msg` z urządzenia w `data.sns.message`. Dla reguł `110502` i `110503` opis nowego alertu zawiera oba pola w formacie `ID (opis)`. W tabeli alarmów na dashboardzie są one w osobnych kolumnach. Opis pochodzi z konkretnego komunikatu SNS, więc integracja działa także dla nowych identyfikatorów.

| Przykład z logu SNS | Znaczenie |
| --- | --- |
| `90 (Remote Access : TeamViewer (HTTP))` | Zapora rozpoznała ruch zdalnego dostępu TeamViewer przez HTTP. O decyzji zapory informuje `action`. |
| `734 (TLS1.3 : 0-RTT not allowed)` | Zapora odnotowała próbę przesłania wczesnych danych TLS 1.3 (0-RTT) w sytuacji, w której ich nie dopuszcza. |
| `122 (Invalid char in SMTP header (ClientCmdNUL))` | Zapora zgłosiła niedozwolony znak NUL w ruchu SMTP. |

Przy analizie sprawdź również akcję `data.sns.action`, klasę `data.sns.alarm_class` i pole `data.sns.risk`, jeśli występuje. Publiczna integracja Elastic tak samo zachowuje `alarmid` jako kod zdarzenia i odsyła do dokumentacji producenta. [Dokumentacja logów Stormshield SNS](https://documentation.stormshield.eu/SNS/v5/en/Content/Description_of_Audit_logs/Configure_logs.htm) · [Pipeline integracji Elastic](https://github.com/elastic/integrations/blob/main/packages/stormshield/data_stream/log/elasticsearch/ingest_pipeline/default.yml)

## MikroTik RouterOS

Moduł rozpoznaje komunikaty zapory z prefiksem `WAZUH-DROP`, logowania i wylogowania z adresem IP oraz dzierżawy IPv4 `assigned` i `deassigned`. Dla obsługiwanego formatu ruchu TCP/UDP wydobywa adresy i porty IPv4 oraz interfejsy. Przy blokadzie w innym układzie pól sam prefiks wciąż umożliwia alert. Zdarzenia mają pola `routeros.*` oraz standardowe pola sieciowe Wazuh, gdy występują w obsługiwanym formacie.

| ID | Poziom | Dopasowanie |
| --- | ---: | --- |
| 110520 | 0 | Wspólna reguła, m.in. udane logowanie, wylogowanie i zwolnienie dzierżawy |
| 110521 | 4 | Blokada z prefiksem `WAZUH-DROP` |
| 110522 | 6 | Nieudane logowanie |
| 110523 | 3 | Przydzielenie dzierżawy IPv4 |

## QNAP QuLog Center

Moduł rozpoznaje komunikaty ze znacznikiem sysloga `qnap-qulog`. Odczytuje treść wpisu, komponent oraz użytkownika i adres klienta, gdy występują w obsługiwanym zapisie. Szczegóły reguł i odbioru logów są w [instrukcji QNAP](qnap.md).

## Testy

Uruchom `python3 tests/run.py` z katalogu repozytorium. Skrypt montuje repozytorium do tymczasowego kontenera tylko do odczytu. W kontenerze najpierw sprawdza konfigurację przez `wazuh-analysisd -t`, następnie uruchamia analizę i przekazuje próbki do `wazuh-logtest`. Sprawdza nazwę dekodera, pola, ID reguły i poziom. Scenariusze korelacji działają we wspólnej sesji i sprawdzają, czy zmiana IP lub urządzenia uniemożliwia przedwczesny alert. Nie potrzeba managera produkcyjnego, indeksatora ani fizycznej zapory.

Na Wazuh 4.14.5 przeszły 53 przypadki syntetyczne. Dodatkowo odtworzono 48 publicznych logów z zestawów Elastic podlinkowanych przez serytia. Wszystkie dopasowały dekoder SNS i zachowały oczekiwane `logtype`. Dwa syntetyczne zdarzenia wysłane przez UDP do lokalnego nasłuchu Wazuh dotarły do `alerts.json` z regułami 110501 i 110523.

Format eksportu i pokrycie zdarzeń na konkretnych urządzeniach należy potwierdzić na ich logach. [Zbieranie próbek SNS](probki-sns.md)

## Źródła

- Publiczny pakiet serytia pokazuje rodziny WELF i przykłady reguł dla blokad, alarmów oraz uwierzytelnienia. Pakiet ma własną licencję GPLv2. Kod i syntetyczne próbki w tym projekcie są własną implementacją na licencji MIT. [serytia/wazuh-stormshield-detection](https://github.com/serytia/wazuh-stormshield-detection)
- Repozytorium phastier dokumentuje formaty Stormshield SNS i MikroTik RouterOS oraz przykłady zbierania zdarzeń dla środowisk wielourządzeniowych. [phastier/wazuh](https://github.com/phastier/wazuh)
- Wbudowany FortiGate w Wazuh stanowi wzorzec dekodowania niezależnych pól `key=value`. Wazuh dostarcza także własne dekodery Cisco ASA, pfSense i Palo Alto. [FortiGate](https://github.com/wazuh/wazuh/blob/v4.14.5/ruleset/decoders/0100-fortigate_decoders.xml) · [Cisco ASA](https://github.com/wazuh/wazuh/blob/v4.14.5/ruleset/decoders/0064-cisco-asa_decoders.xml) · [pfSense](https://github.com/wazuh/wazuh/blob/v4.14.5/ruleset/decoders/0455-pfsense_decoders.xml) · [Palo Alto](https://github.com/wazuh/wazuh/blob/v4.14.5/ruleset/decoders/0505-paloalto_decoders.xml)
- Dokumentacja producentów opisuje pola i transport. [Stormshield SNS](https://documentation.stormshield.com/SNS/v4/en/Content/Description_of_audit_logs/) · [MikroTik RouterOS](https://help.mikrotik.com/docs/spaces/ROS/pages/328094/Log) · [Wazuh syslog](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html)
