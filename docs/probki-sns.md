# Próbki do weryfikacji Stormshield SNS

Wystarczy kilka surowych linii z urządzenia. Najbardziej przydatne są po 1–3 wpisy z ruchu dozwolonego i blokowanego, alarmów, udanego i nieudanego logowania, VPN i audytu administratorów. Dodaj jeden wpis, który sprawia trudność, jeśli taki masz. Wybierz zdarzenia już zarejestrowane przez urządzenie.

## Pobranie

Najlepszym źródłem jest dedykowany plik logów na odbiorniku sysloga, który zawiera komunikaty wysłane przez SNS. Skopiuj ograniczony fragment potrzebnych kategorii do lokalnego pliku roboczego. Przy wyciąganiu z istniejącego `archives.json` Wazuh wybierz `full_log` odpowiadający znanemu nadawcy. Zachowaj jedną kompletną linię na zdarzenie, z nagłówkiem syslog, jeśli jest obecny. Jeśli masz tylko tabelę logów w panelu SNS, poszukaj eksportu surowej treści. Do testu dekodera potrzebne są linie z `id=firewall` i `logtype=`.

Jeśli masz już włączone `archives.json` i znasz wartość pola `location` dla zapory, poniższe polecenie zapisze do 30 ostatnich pasujących linii. Podmień wartość przykładową na tę z Twojego Wazuh. Plik roboczy zawiera dane przed anonimizacją.

```bash
umask 077
sudo jq -r --arg sender '192.0.2.10' \
  'select(.location == $sender) | .full_log // empty | select(contains("id=firewall"))' \
  /var/ossec/logs/archives/archives.json | tail -n 30 > stormshield-roboczy.log
```

## Anonimizacja i pakowanie

1. W lokalnej kopii zamień adresy IPv4 konsekwentnie na adresy z `192.0.2.0/24`, `198.51.100.0/24` lub `203.0.113.0/24`. Dla IPv6 użyj `2001:db8::/32`. Gdy ten sam adres pojawia się kilkukrotnie, użyj tego samego zamiennika.
2. Zamień nazwy użytkowników, domeny, hosty, identyfikatory urządzeń, adresy MAC, nazwy interfejsów i dane organizacji na fikcyjne odpowiedniki. Sprawdź też wartości `msg`, URL, pola audytu z argumentami poleceń i fragmenty certyfikatów. Usuń hasła, tokeny, klucze i dane osobowe. Zachowaj klucze WELF, cudzysłowy, kolejność pól oraz takie wartości jak `logtype`, `action`, `error` i `class`, które sterują regułami.
3. Zapisz wynik w UTF-8 jako `stormshield-sample.log` i przejrzyj go przed wysłaniem. Dołącz wersję SNS, sposób odbioru (bezpośrednio lub przez przekaźnik) i transport. Sam plik tekstowy wystarczy. Jeśli wolisz archiwum, z katalogu ze sprawdzonym plikiem uruchom:

```bash
tar -czf stormshield-sample.tar.gz stormshield-sample.log
tar -tzf stormshield-sample.tar.gz
```

Załącz wyłącznie plik po anonimizacji lub archiwum, które go zawiera.
