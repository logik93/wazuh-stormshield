# Dashboardy urządzeń dla Wazuh

Każde urządzenie ma własny dashboard i plik importu.

| Dashboard | Co pokazuje | Obiekty w pliku |
| --- | --- | ---: |
| [Stormshield SNS · Monitorowanie](stormshield-sns.ndjson) | Blokady, alarmy, VPN, logowania i techniki MITRE | 16 |
| [MikroTik RouterOS · Ruch i dostęp](mikrotik-routeros.ndjson) | Źródła, cele, porty i interfejsy blokad, metody logowania oraz klienci DHCP | 13 |
| [QNAP QuLog · Ochrona danych i dostęp](qnap-qulog.ndjson) | Logowania, zmiany i usunięcia plików SMB, źródła sysloga, kopie oraz alerty sprzętowe | 17 |

W każdym dashboardzie ustaw przedział czasu i rozwiń wpis w panelu **Ostatnie alerty**. Jeżeli urządzenie nie zarejestrowało danego zdarzenia w wybranym czasie, odpowiedni licznik pokaże zero, a tabela może być pusta. Dla QNAP-a najpierw [skonfiguruj odbiór logów QuLog](../docs/qnap.md).

**Stormshield SNS · Monitorowanie** pokazuje alerty z indeksów `wazuh-alerts-*`. Jeden plik NDJSON zawiera dashboard i wszystkie 15 paneli. Liczniki i wykres pokazują sytuację w wybranym czasie. Dziennik ostatnich alertów zawiera opis i adresy, a tabele pokazują, czego dotyczyły blokady i jak zapora zareagowała na alarmy.

[**Pobierz plik do importu**](./stormshield-sns.ndjson)

## Aktualizacja istniejącego dashboardu

Zaimportuj właściwy plik z opcją **Overwrite** w tym samym tenancie. Zostaw wyłączone **Create new copies**, aby kolejne aktualizacje trafiały do tych samych obiektów. Powyższa tabela podaje liczbę obiektów dla każdego pliku. Oryginalny dashboard Stormshield ma identyfikator `logik93-stormshield-sns-overview`, widoczny w adresie po `#/view/`. Jeśli poprzedni import utworzył kopię z innym identyfikatorem, otwórz dashboard o oryginalnym identyfikatorze po aktualizacji. Jeśli korzystasz z własnego ID wzorca indeksu, użyj go również przy aktualizacji.

Jeżeli w **Visualize** widzisz sześć angielskich pozycji zaczynających się od `Stormshield -`, to wizualizacje starszego pakietu. Nowy dashboard obejmuje odpowiadające im widoki. Jeśli chcesz uporządkować listę, wyeksportuj poprzedni dashboard wraz z wizualizacjami jako kopię, sprawdź nowy widok, a potem usuń w **Saved Objects** stary dashboard i tylko te sześć wizualizacji, o ile inne dashboardy ich nie używają. Zachowaj wzorzec indeksu alertów.

## Import do Wazuh Dashboard

1. W obszarze (tenant) używanym do przeglądania alertów Wazuh przejdź do **Dashboard Management → Saved Objects → Import**.
2. Wybierz plik NDJSON dla swojego urządzenia. Przy pierwszym imporcie możesz zostawić opcję nadpisywania wyłączoną. Włącz ją przy aktualizacji tego samego dashboardu.
3. Plik odwołuje się do standardowego wzorca indeksu `wazuh-alerts-*`. Jeśli importer zgłosi brakującą referencję, wskaż istniejący wzorzec alertów Wazuh z polem czasu `timestamp`. Jeżeli Twoja wersja importera nie pozwala przypisać referencji, odczytaj ID wzorca w **Index Patterns** i zmień w pliku wartości `"id":"wazuh-alerts-*"` w referencjach typu `index-pattern`.
4. Otwórz wybrany dashboard w **Dashboards** i ustaw zakres czasu, np. **Last 24 hours**.

## Sprawdzenie źródła logów QNAP

W **Ostatnich alertach** i **Źródłach sysloga** pole `location` pokazuje adres nadawcy przy odbiorze bezpośrednim przez Wazuh. W logach ze starszego przekaźnika pole może zawierać ścieżkę do pliku. Kolumna `data.srcip` opisuje klienta z komunikatu, np. IP osoby logującej się do NAS-a. Aby przefiltrować dashboard do konkretnego NAS-a, wybierz w **Add filter** pole `location`.

Dla logów dostępu `qulogd` najważniejsze widoki są u góry: błędy logowania, zmiany i usunięcia plików SMB. W dzienniku zmian sprawdzisz, kto wykonał operację, na jakim zasobie i z jakiego adresu. Odczyty SMB pozostają w archiwum, jeśli manager archiwizuje wszystkie logi. Widoki systemowe poniżej pokazują zdarzenia, gdy QuLog je wysyła.

Domyślny dashboard jest przeznaczony do logów QuLog. Osobny [panel pojemności](qnap-volumes-snmp.ndjson) można dołączyć w instalacji, która zbiera [pomiary SNMPv3](../docs/qnap.md#wolne-miejsce-na-woluminach).

## Brak danych na dashboardzie MikroTik

Jeśli tabelki pokazują **No results found**, w **Discover** ustaw okres, w którym RouterOS wysyłał logi, i sprawdź filtr `rule.groups: "mikrotik" AND rule.groups: "routeros"`. Dla blokad sprawdź prefiks `WAZUH-DROP` i regułę `110521`. Wybrane logowania i przydziały DHCP mają reguły `110522` i `110523`.

Panele interfejsów, metod logowania i klientów DHCP pokazują komunikat o braku danych, dopóki w wybranym okresie nie pojawi się alert z danym polem. Jeżeli nadal widzisz **Could not locate that index-pattern-field** w tych panelach, zaimportuj aktualny plik MikroTik z opcją **Overwrite** i otwórz oryginalny dashboard `logik93-mikrotik-routeros-overview`. [Odbiór logów RouterOS](../docs/instalacja.md#mikrotik-routeros-7)

## Jak czytać dashboard Stormshield

1. Ustaw **Last 24 hours** na początek. Liczniki pokazują alerty z wybranego okresu.
2. W panelu **Ostatnie alerty** przeczytaj opis zdarzenia. Użyj strzałki przy wpisie, aby rozwinąć szczegóły, w tym oryginalny log, jeżeli zapisał go Wazuh.
3. Porównaj **Źródła blokad**, **Cele blokad** i **Porty docelowe blokad**. Aby zawęzić cały dashboard do jednego adresu, użyj **Add filter**. Wybierz pole `data.srcip` dla źródła lub `data.dstip` dla celu i wpisz adres z tabeli.
4. W panelu **Decyzje zapory przy alarmach** sprawdź, ile razy ruch został zablokowany, ile razy zapora przepuściła ruch mimo alarmu oraz ile wpisów miało inną lub nieznaną akcję. Szczegółowe nazwy alarmów są w panelu **Najczęstsze alarmy SNS**.

Dashboard pokazuje nowe alerty z grup `stormshield` i `sns`. Liczniki, wykres w czasie, dziennik, źródła i cele blokad, porty, decyzje przy alarmach oraz zestawienie MITRE uwzględniają również historyczne alerty pakietu serytia, rozpoznane po dekoderze `stormshield` i regułach `100301`, `100303`, `100310`, `100311`, `100320` i `100321`. Panele według zapory, ID alarmu, konta i typu VPN korzystają z pól nowej integracji. Jeśli nowe pola są dostępne w Discover, lecz panel nadal ich nie rozpoznaje, odśwież listę pól wzorca indeksu.

W tabeli **Techniki MITRE ATT&CK** wiersz **Bez oznaczenia MITRE** zlicza alerty bez `rule.mitre.id`, na przykład zwykłe blokady ruchu. Techniki pojawiają się po zarejestrowaniu faktycznie oznaczonych alertów. W nowej integracji próg powtarzających się błędów logowania uruchamia regułę `110508` z oznaczeniem `T1110`.

Liczniki pokazują dokumenty alertów. Licznik blokad uwzględnia także pojedyncze alerty korelacji `110509`. Rozkład alarmów grupuje wpisy według identyfikatora alarmu Stormshield i pokazuje opis z pola `msg`, a wykres w czasie według poziomu reguły Wazuh.

| Panel | Reguły lub pola |
| --- | --- |
| Wszystkie alerty, oś czasu, zapory | `rule.groups`, `timestamp`, `rule.level`, `data.sns.device` |
| Blokady ruchu, źródła, cele i porty | `110501`, `110509`, `data.srcip`, `data.dstip`, `data.dstport` |
| Decyzje przy alarmach | `data.sns.action` lub `data.action` w starszych alertach |
| Alarmy | `110502`, `110503`, `data.sns.alarm_id`, `data.sns.message` |
| Nieudane logowania | `110504`, `110505`, `110508`, `data.srcuser` |
| Błędy VPN | `110506`, `data.sns.logtype` |
| Techniki MITRE ATT&CK | `rule.mitre.id` i licznik alertów bez tego pola |

Import i zapytania paneli sprawdzono w OpenSearch Dashboards 2.19.4 z próbkami zapisanymi według mapowania Wazuh 4.14.5.

Panele pojemności QNAP oraz interfejsów, metod logowania i klientów DHCP MikroTika używają wbudowanej wizualizacji Vega. Odczytują indeksy `wazuh-alerts-*` z aktualnym zakresem czasu i filtrami dashboardu. W instalacji z inną nazwą indeksów zmień `index` w specyfikacjach tych paneli. Specyfikacje w plikach NDJSON można odtworzyć przez `python3 dashboard/build_device_panels.py`.
