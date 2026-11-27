# Wazuh · Stormshield SNS, MikroTik RouterOS i QNAP

Dekodery i reguły dla managera Wazuh. Stormshield SNS wysyła komunikaty WELF przez syslog. Moduł RouterOS obsługuje zdarzenia zapory, logowania i dzierżawy DHCP w formacie BSD syslog. Moduł QNAP analizuje logi QuLog Center przesyłane do nasłuchu syslog Wazuh.

| Moduł | Dekodowane zdarzenia | Alerty |
| --- | --- | --- |
| Stormshield SNS | Ruch i NAT, alarmy, uwierzytelnianie, VPN, audyt administracyjny, system i inne rodziny WELF | Blokady ruchu, alarmy, nieudane uwierzytelnienia i VPN, wybrane polecenia konfiguracji, powtarzające się blokady i błędy logowania |
| MikroTik RouterOS 7 | Blokady z prefiksem `WAZUH-DROP`, logowania i wylogowania, przydzielenie i zwolnienie dzierżawy IPv4 | Blokady ruchu, błędy logowania, przydzielenie dzierżawy |
| QNAP QuLog Center | Dostęp do NAS-a, dyski i RAID, kopie, replikacja, migawki, sprzęt i zasilanie oraz pomiary woluminów przez SNMPv3 | Wynik logowania i ochrony danych oraz problemy z pamięcią masową lub sprzętem |

Dla Fortinet FortiGate, Cisco ASA, pfSense i Palo Alto skorzystaj z dekoderów dostarczanych z Wazuh. W przypadku FortiGate wysyłaj natywny format `key=value`. Dobierz format pozostałych urządzeń na podstawie dekoderów zainstalowanej wersji i potwierdź dopasowanie w `wazuh-logtest`.

- [Instalacja, konfiguracja sysloga i wycofanie zmian](docs/instalacja.md)
- [Pola, reguły, testy i źródła](docs/dekodery-i-reguly.md)
- [Jak zebrać i zanonimizować próbki ze Stormshielda](docs/probki-sns.md)
- [Dashboardy Stormshield, MikroTik i QNAP oraz instrukcja importu](dashboard/README.md)
- [Konfiguracja QNAP QuLog Center](docs/qnap.md)
- [Licencja MIT](LICENSE)

## Instalacja na Linuksie

Na hoście managera Wazuh uruchom `sudo ./install.sh` i wybierz moduły. Po instalacji QNAP możesz od razu uruchomić kreator odbioru sysloga. Aby je usunąć, uruchom `sudo ./uninstall.sh`. [Instrukcja konfiguracji, migracji i testu po wdrożeniu](docs/instalacja.md)

## Szybki test

Z katalogu projektu uruchom `python3 tests/run.py`. Test wymaga Pythona 3 i działającego Dockera. Używa obrazu `wazuh/wazuh-manager:4.14.5` i sprawdza pola oraz reguły na logach syntetycznych. Wersję i sposób weryfikacji opisuje [dokumentacja testów](docs/dekodery-i-reguly.md#testy).
