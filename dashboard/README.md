# Dashboard Stormshield SNS

**Stormshield SNS · Monitorowanie** pokazuje alerty z indeksów `wazuh-alerts-*`. Jeden plik NDJSON zawiera dashboard i wszystkie 12 wizualizacji. Są w nim liczniki, wykres alertów w czasie według poziomu reguły i tabele z adresami źródłowymi, portami, zaporami, alarmami, kontami, typami VPN i technikami MITRE ATT&CK.

[**Pobierz plik do importu**](./stormshield-sns.ndjson)

## Aktualizacja istniejącego dashboardu

Zaimportuj plik z opcją **Overwrite**. Identyfikator dashboardu i identyfikatory dotychczasowych 11 paneli są takie same. Jeśli korzystasz z własnego ID wzorca indeksu, użyj go również przy aktualizacji.

Jeżeli w **Visualize** widzisz sześć angielskich pozycji zaczynających się od `Stormshield -`, to wizualizacje starszego pakietu. Nowy dashboard obejmuje odpowiadające im widoki. Jeśli chcesz uporządkować listę, wyeksportuj poprzedni dashboard wraz z wizualizacjami jako kopię, sprawdź nowy widok, a potem usuń w **Saved Objects** stary dashboard i tylko te sześć wizualizacji, o ile inne dashboardy ich nie używają. Zachowaj wzorzec indeksu alertów.

## Import do Wazuh Dashboard

1. W obszarze (tenant) używanym do przeglądania alertów Wazuh przejdź do **Dashboard Management → Saved Objects → Import**.
2. Wybierz `stormshield-sns.ndjson`. Przy pierwszym imporcie możesz zostawić opcję nadpisywania wyłączoną. Włącz ją przy aktualizacji tego samego dashboardu.
3. Plik odwołuje się do standardowego wzorca indeksu `wazuh-alerts-*`. Jeśli importer zgłosi brakującą referencję, wskaż istniejący wzorzec alertów Wazuh z polem czasu `timestamp`. Jeżeli Twoja wersja importera nie pozwala przypisać referencji, odczytaj ID wzorca w **Index Patterns** i zmień w pliku wartości `"id":"wazuh-alerts-*"` w referencjach typu `index-pattern`.
4. Otwórz **Stormshield SNS · Monitorowanie** w **Dashboards** i ustaw zakres czasu, np. **Last 24 hours**.

Dashboard korzysta z obu grup reguł `stormshield` i `sns`. Po przejściu ze starszego zestawu do widoku trafią nowe alerty naszej integracji. Panele z kontami i VPN zaczną pokazywać dane, gdy manager zapisze odpowiednie alerty. Jeśli nowe pola są dostępne w Discover, lecz panel nadal ich nie rozpoznaje, odśwież listę pól wzorca indeksu.

Liczniki pokazują dokumenty alertów. Licznik blokad uwzględnia także pojedyncze alerty korelacji `110509`. Rozkład alarmów grupuje wpisy według identyfikatora alarmu Stormshield, a wykres w czasie według poziomu reguły Wazuh.

| Panel | Reguły lub pola |
| --- | --- |
| Wszystkie alerty, oś czasu, zapory | `rule.groups`, `timestamp`, `rule.level`, `data.sns.device` |
| Blokady ruchu, źródła i porty | `110501`, `110509`, `data.srcip`, `data.dstport` |
| Alarmy | `110502`, `110503`, `data.sns.alarm_id` |
| Nieudane logowania | `110504`, `110505`, `110508`, `data.srcuser` |
| Błędy VPN | `110506`, `data.sns.logtype` |
| Techniki MITRE ATT&CK | `rule.mitre.id`, obecnie T1110 przy regule `110508` |

Import i zapytania paneli sprawdzono w OpenSearch Dashboards 2.19.4 z próbkami zapisanymi według mapowania Wazuh 4.14.5.
