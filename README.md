# hAI.cariddi

Cariddi als Portainer-Repository-Stack mit Weboberflaeche und automatischem GHCR-Build. Portainer zieht nur das fertige Image und baut nicht lokal. Kein Docker-Socket.

## Herkunft

Upstream: https://github.com/edoardottt/cariddi (GPL-3.0). Fixierter Quellstand: `39aebc1ce7e43a2c59de194d0d1e29a034c8ab3c`; das Dockerfile prueft den Commit vor dem Build. Der verwendete Upstream-Quelltext inklusive LICENSE liegt im Image unter `/usr/share/cariddi/source`. Die eigenen Wrapper- und Deployment-Dateien (web.py, runner.py, Compose, Workflow) stehen unter MIT, siehe LICENSE.

## Weboberflaeche

Nach dem Deployment: `http://<Host>:8666` (Port ueber `WEB_PORT` aenderbar).

- Login mit `ADMIN_PASSWORD` (Pflicht, mindestens 6 Zeichen; ohne Passwort startet der Container nicht)
- Ziele eingeben: eine http(s)-URL pro Zeile, maximal 50, keine Zugangsdaten in URLs
- Optionen als Formular: Parallelitaet, Delay, Tiefe, Timeout, Endpoints, Secrets, Fehler, Infos, Dateiendungen, zufaelliger User-Agent, optional Intensiv-Modus (siehe ALLOWED_HOSTS)
- Scan starten und stoppen; es laeuft immer nur ein Scan gleichzeitig
- Laufhistorie mit Status, Exitcode, Zielen, Argumenten, stdout/stderr (Ende der Logs, Auto-Refresh waehrend des Laufs) und Download
- Einzelne Laeufe loeschen
- Vor jedem Start muss die Berechtigung fuer alle Ziele bestaetigt werden

Es gibt bewusst kein Freitextfeld fuer beliebige Kommandozeilenargumente: Optionen werden serverseitig geprueft und in eine feste Argumentliste uebersetzt (keine Shell).

## Netzwerk

Der Stack haengt am externen Docker-Netzwerk `highfishNetwork`. Dieses Netzwerk muss in Portainer vor dem Deployment bereits existieren (Networks > Add network, Name exakt `highfishNetwork`), sonst schlaegt das Deployment fehl. Innerhalb des Netzwerks ist der Dienst unter `cariddi:8080` erreichbar; auf dem Host ueber den veroeffentlichten Port 8666.

## Build und Deployment

Push auf main startet `.github/workflows/build.yml`: Python-Syntax, Compose-Validierung, Selftest, HTTP-Smoke-Test (Healthcheck und Login-Redirect) und anschliessend Veroeffentlichung fuer AMD64/ARM64 nach `ghcr.io/jbkunama1/hai.cariddi` (Tags `latest`, `sha-<commit>`, `v*`). Ein Commit ist noch kein erfolgreicher Build: erst den gruenen Workflow und das Package pruefen. GHCR-Pakete koennen anfangs privat sein: Sichtbarkeit auf oeffentlich stellen oder GHCR in Portainer mit einem Token (read:packages) hinterlegen.

Portainer: Stacks > Add stack > Repository

| Einstellung | Wert |
|---|---|
| Name | hai-cariddi |
| Repository URL | https://github.com/jbkunama1/hAI.cariddi |
| Reference | refs/heads/main |
| Compose path | docker-compose.yml |

## Umgebungsvariablen

| Variable | Standard | Bedeutung |
|---|---|---|
| ADMIN_PASSWORD | Pflicht | Login-Passwort, mindestens 6 Zeichen |
| WEB_PORT | 8666 | Host-Port der Oberflaeche |
| BIND_ADDR | 0.0.0.0 | Host-Adresse; z. B. 127.0.0.1 hinter Reverse-Proxy |
| ALLOWED_HOSTS | leer | Komma-Liste erlaubter Domains inkl. Subdomains (z. B. `example.com`). Leer: alle oeffentlichen Hosts erlaubt, aber ohne Intensiv-Modus. `*`: alle Hosts erlaubt und Intensiv-Modus (-intensive) freigeschaltet |
| ALLOW_PRIVATE_TARGETS | false | true erlaubt private/lokale Adressen (Heimnetz-Ziele) |
| COOKIE_SECURE | false | true setzen, sobald die UI nur ueber HTTPS erreichbar ist |
| SCAN_TIMEOUT_SECONDS | 1800 | Maximale Laufzeit eines Scans (60 bis 86400) |
| IMAGE_TAG | latest | Fuer reproduzierbare Deployments sha-Tag verwenden |

## Sicherheit

- Die UI nicht ungeschuetzt ins Internet stellen: HTTPS ueber Reverse-Proxy oder Cloudflare Tunnel/Access davorschalten, dann `COOKIE_SECURE=true` und idealerweise `BIND_ADDR=127.0.0.1`. Ohne TLS laufen Passwort und Session unverschluesselt.
- Die Mindestlaenge des Passworts betraegt nur 6 Zeichen. Kurze Passwoerter sind leicht zu erraten: fuer Erreichbarkeit ausserhalb des Heimnetzes ein deutlich laengeres Passwort waehlen und die UI zusaetzlich per Reverse-Proxy/Zugriffsschutz absichern.
- Mit `ALLOWED_HOSTS=*` ist der Intensiv-Modus fuer beliebige Ziele moeglich: Cariddi crawlt dann auch Subdomains der Ziele (2nd-Level-Domain-Match). Das erweitert den Scan-Umfang erheblich. Nur Ziele eintragen, fuer die eine Berechtigung vorliegt, einschliesslich ihrer Subdomains.
- Anmeldung: Session-Cookie (HttpOnly, SameSite=Strict, 8 Stunden), CSRF-Token bei allen Aktionen, Sperre nach 5 Fehlversuchen pro IP und 5 Minuten. Hinter einem Proxy sieht der Container nur die Proxy-IP; die Sperre gilt dann gemeinsam.
- Ziele werden per DNS aufgeloest; nicht-oeffentliche Adressen (localhost, RFC1918, Link-Local) sind standardmaessig blockiert. Das ist keine vollstaendige Netzwerkgrenze: Redirects, spaetere DNS-Aenderungen und gefundene Links koennen auf andere Hosts fuehren. Fuer strikte Scopes zusaetzlich ausgehenden Verkehr per Firewall begrenzen.
- Andere Container im Netzwerk highfishNetwork koennen die Oberflaeche ebenfalls erreichen; ALLOW_PRIVATE_TARGETS=true erlaubt zudem Scans gegen interne Docker-Adressen. Nur bewusst aktivieren.
- Sessions liegen im Speicher: ein Neustart meldet alle ab.
- Nur eigene oder schriftlich freigegebene Ziele pruefen. Ergebnisse (Logs mit moeglichen Secrets) liegen im Volume `cariddi_data` unter `/data/runs`; Zugriff beschraenken, nicht committen, Backups schuetzen. Es gibt keine automatische Loeschung.

## Diagnose

- Container startet nicht: Logs pruefen; `ADMIN_PASSWORD` fehlt oder ist zu kurz, oder Compose meldet die Pflichtvariable.
- Deployment meldet `network highfishNetwork not found`: Netzwerk in Portainer anlegen (Name exakt, gleiche Gross-/Kleinschreibung) und Stack neu deployen.
- Option Intensiv fehlt in der UI: `ALLOWED_HOSTS` ist leer; auf `*` oder eine Domain-Liste setzen und Stack neu deployen.
- Login nicht moeglich nach HTTPS-Umstellung: `COOKIE_SECURE=true` nur mit HTTPS setzen.
- manifest unknown: GHCR-Build/Tag pruefen; unauthorized: Package-Sichtbarkeit oder Portainer-Registry-Login pruefen.
- Lauf bleibt `interrupted`: Container wurde waehrend des Scans beendet; Ergebnis ist unvollstaendig.
- Permission denied bei eigenen Bind-Mounts: Ziel muss fuer UID/GID 10001 schreibbar sein.
- `runner.py` bleibt als Kommandozeilen-Alternative im Image (`python /app/runner.py --once` mit `CARIDDI_TARGETS` in der Container-Umgebung), ist aber im Standard-Stack nicht verdrahtet.
