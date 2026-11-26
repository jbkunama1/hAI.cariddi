# AI-MEMORY: hAI.cariddi

Kontextdatei fuer KI-Assistenten. Sie fasst Ziel, Architektur, Entscheidungen und Stand zusammen, damit eine neue Sitzung ohne Vorwissen weiterarbeiten kann. Bei jeder relevanten Aenderung mitpflegen. Keine Zugangsdaten oder Secrets eintragen.

## Projekt

- Repository: https://github.com/jbkunama1/hAI.cariddi
- Ziel: Cariddi (Crawler fuer Endpoints, Secrets, Fehler, Infos, Dateien) als Portainer-Repository-Stack mit GHCR-Image und Weboberflaeche zum Verwalten und Starten berechtigter Scans.
- Upstream: https://github.com/edoardottt/cariddi (GPL-3.0), fixiert auf Commit `39aebc1ce7e43a2c59de194d0d1e29a034c8ab3c`.
- Image: `ghcr.io/jbkunama1/hai.cariddi` (Tags latest, sha-<commit>, v*). Portainer baut nicht lokal, es zieht nur das Image.
- Eigene Dateien stehen unter MIT, Upstream-Quelltext liegt im Image unter `/usr/share/cariddi/source`.

## Architektur

- `web.py`: Weboberflaeche nur mit Python-Standardbibliothek (http.server), kein Framework. Kein JavaScript, weil die Content-Security-Policy Skripte verbietet; Rueckfragen und Tooltips laufen ueber Formulare und CSS.
- `runner.py`: Kommandozeilen-Alternative, im Standard-Stack nicht verdrahtet.
- `Dockerfile`, `docker-compose.yml`, `.github/workflows/build.yml` (Syntax, Compose-Validierung, Selftest, HTTP-Smoke-Test, Multi-Arch-Build).
- Daten: Volume `cariddi_data` unter `/data/runs/<run-id>/` mit `meta.json`, `stdout.log`, `stderr.log`. Run-ID-Format `YYYYMMDDTHHMMSSZ-<8 hex>`.
- Cariddi bekommt Ziele ueber stdin; die Argumente werden serverseitig aus dem Formular gebaut (kein Freitext, keine Shell). Es laeuft immer nur ein Scan gleichzeitig.
- Container: read-only, cap_drop ALL, no-new-privileges, 1 CPU, 128 Prozesse, `mem_limit: 1g`, Healthcheck auf `/healthz`.

## Beschlossene Entscheidungen

| Thema | Entscheidung |
|---|---|
| Port | Host 8666 auf Container 8080 (`WEB_PORT`) |
| Netzwerk | externes Docker-Netzwerk `highfishNetwork`, muss vor dem Deployment existieren |
| Login | `ADMIN_PASSWORD` Pflicht, mindestens 6 Zeichen |
| Private Ziele | standardmaessig gesperrt, `ALLOW_PRIVATE_TARGETS=true` erlaubt sie |
| ALLOWED_HOSTS | leer: alle oeffentlichen Hosts, ohne Intensiv-Modus. `*`: alle Hosts und `-intensive` freigeschaltet. Domain-Liste: nur diese Domains |
| Berechtigung | vor jedem Scan Checkbox-Bestaetigung Pflicht; maximal 50 Ziele |
| Bericht | `/run/<id>/report`: alle Treffer ohne Zeilen- oder Groessenlimit, Zusammenfassung am Ende, Secret-Werte gekuerzt (erste 4 Zeichen und Laenge) |
| Max. Laufzeit | Feld pro Scan, 1 bis 1440 Minuten, Vorgabe aus `SCAN_TIMEOUT_SECONDS` (1800) |
| Aufbewahrung | `RETENTION_DAYS=7`, stuendliche Bereinigung, Hinweis "(wird geloescht in x Tagen)" hinter jedem Lauf, 0 schaltet ab |
| Loeschen | Button je Lauf und "Alle beendeten Laeufe loeschen", jeweils mit Bestaetigungsseite; laufender Scan nicht loeschbar |
| Speicher | `mem_limit: 1g` |
| Image-Tag | bleibt bewusst `latest` |
| Hilfe | rechtes Hilfe-Panel mit Kurzanleitung und Pro/Contra je Option, dazu "?"-Tooltips; Profile Vorsichtig, Schnell, Gruendlich sind Empfehlungen |
| UI-Texte | ASCII-Schreibweise (ae, oe, ue, ss), Sprache Deutsch |

## Aktueller Stand

Wichtige Commits auf `main`, neueste zuletzt:

- `3e6406b`: `ALLOWED_HOSTS=*` erlaubt Intensiv-Scans fuer alle Hosts
- `05cb405`: lesbarer Ergebnisbericht mit Zusammenfassung
- `8ab42be`: Bericht ohne Zeilen- und Groessenlimit
- `145607a`: Aufbewahrung, 1g Speicherlimit, Max. Laufzeit pro Scan, Hilfe-Panel
- `a9663b7`: manuelle Loeschen-Buttons mit Rueckfrage

## Nicht verifiziert

- Ob die GHCR-Builds (GitHub Actions) gruen sind und das Image verfuegbar ist.
- Ob der Stack in Portainer erfolgreich deployt wurde.
- Der Code wurde nicht lokal ausgefuehrt; Tests laufen nur als Selftest in CI.
- Laut bisherigem Verlauf wurden keine Scans gestartet.

## Offene Punkte und Ideen

Nur vorgeschlagen, nicht beschlossen:

- Obergrenze der Parallelitaet von 20 auf 100 anheben; Voreinstellungen (Delay 0, Parallelitaet 20) oder Profil-Schalter im Formular.
- Optionaler Schalter, um Secrets im Bericht im Klartext anzuzeigen (bisher bewusst gekuerzt).
- Mehrere Scans parallel (bisher genau einer).
- Passwort-Mindestlaenge von 6 Zeichen ist schwach; fuer Zugriff ausserhalb des Heimnetzes Reverse-Proxy mit HTTPS (`COOKIE_SECURE=true`) und laengeres Passwort einplanen.
- Sehr grosse Berichte laden alle Treffer in den Arbeitsspeicher; bei Problemen Limit oder Paginierung neu bewerten.

## Arbeitsweise

- Schreibende GitHub-Aktionen erst nach ausdruecklicher Bestaetigung; danach mit exakt dem bestaetigten Inhalt pushen.
- `push_files` braucht vollstaendige Dateiinhalte; deshalb vor Aenderungen die aktuelle Datei lesen und sie ganz neu schreiben.
- Aenderungen immer mit README, Selftest in `web.py` und diesem Dokument abgleichen.
- Nach jedem Push den GitHub-Actions-Lauf pruefen; ein Commit ist noch kein erfolgreicher Build.
- Nur eigene oder schriftlich freigegebene Ziele scannen; die Berechtigungsabfrage nicht entfernen.
