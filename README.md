# hAI.cariddi

Cariddi als Portainer-Repository-Stack mit automatischem GHCR-Build. Keine Weboberflaeche, kein offener Port, kein Docker-Socket. Portainer zieht nur das fertige Image und baut nicht lokal.

## Herkunft

Upstream: https://github.com/edoardottt/cariddi

Fixierter Quellstand: `39aebc1ce7e43a2c59de194d0d1e29a034c8ab3c`. Das Dockerfile prueft den Commit vor dem Build. Der vollstaendige verwendete Upstream-Quelltext einschliesslich LICENSE und go.mod/go.sum liegt im Image unter `/usr/share/cariddi/source`. Cariddi ist GPL-3.0-lizenziert; seine Urheber- und Lizenzhinweise bleiben erhalten. Die eigenen Wrapper- und Deployment-Dateien dieses Repositorys stehen unter MIT, siehe LICENSE.

## Build

Push auf main startet `.github/workflows/build.yml`: Python-Syntax und Compose-Konfiguration pruefen, AMD64-Smoke-Test ohne Netzwerk und anschliessend AMD64/ARM64 nach GHCR publizieren. Tags: `latest`, `sha-<commit>` und Versions-Tags bei `v*`. Fuer Builds genuegt der automatische GITHUB_TOKEN mit packages:write; keine Zugangsdaten ins Repository schreiben.

Image: `ghcr.io/jbkunama1/hai.cariddi:latest`

Wichtig: Ein Commit ist noch kein erfolgreicher Image-Build. Vor dem Deployment den gruenen Workflow und das veroeffentlichte Package kontrollieren. GHCR-Pakete koennen anfangs privat sein: entweder in den Package-Einstellungen oeffentlich schalten oder GHCR in Portainer mit Benutzername und einem Token mit read:packages hinterlegen.

## Portainer: direkt aus Git

Stacks > Add stack > Repository

| Einstellung | Wert |
|---|---|
| Name | hai-cariddi |
| Repository URL | https://github.com/jbkunama1/hAI.cariddi |
| Reference | refs/heads/main |
| Compose path | docker-compose.yml |

Der Stack startet standardmaessig im Idle-Modus. Es wird kein Scan ausgefuehrt. Keine Portfreigabe erforderlich. Ergebnisse bleiben im benannten Volume cariddi_data des Stacks erhalten. Nicht das Volume loeschen, wenn Ergebnisse erhalten bleiben sollen.

## Konfiguration in Portainer

| Variable | Standard | Bedeutung |
|---|---|---|
| IMAGE_TAG | latest | Fuer reproduzierbare Deployments sha-Tag verwenden |
| SCAN_ENABLED | false | Nur true aktiviert automatische Ausfuehrung beim Containerstart |
| CARIDDI_TARGETS | leer | Eine ausdruecklich autorisierte http(s)-URL pro Zeile |
| CARIDDI_ARGS_JSON | siehe Compose | JSON-Array mit Cariddi-Argumenten; kein Shell-eval |
| SCAN_INTERVAL_SECONDS | 0 | 0: einmal pro Containerstart, dann idle; sonst Pause nach jedem Lauf |
| SCAN_TIMEOUT_SECONDS | 1800 | Maximale Laufzeit eines Scans |

Standardargumente: `["-c","5","-d","1","-md","2","-t","10","-e","-json"]`. Das begrenzt Parallelitaet und Tiefe; es aktiviert kein intensives Subdomain-Crawling. Fuer weitere Optionen die Upstream-Dokumentation lesen.

Fuer einen gewollten Einmallauf Ziele setzen, SCAN_ENABLED=true und SCAN_INTERVAL_SECONDS=0 einstellen. Achtung: Neustart oder Redeploy startet bei weiterhin aktiviertem SCAN_ENABLED erneut einen Scan! Danach wieder false setzen, wenn das nicht gewuenscht ist.

Alternativ bei SCAN_ENABLED=false ueber Portainer > Container > Console einen expliziten Lauf starten:

```sh
python /app/runner.py --once
```

Dabei werden die konfigurierten Umgebungsvariablen genutzt. Nicht parallel zum automatischen Runner starten. Keine Beispielziele werden automatisch angegriffen.

## Ergebnisse und Diagnose

Jeder Lauf erstellt `/data/runs/<UTC-Zeit>-<ID>/` mit stdout.log, stderr.log und status.json (Status, Exitcode und Zeitstempel). stdout.log enthaelt bei -json die Cariddi-Ausgabe, ist aber nicht als einzelnes JSON-Dokument garantiert. Eigene Ausgabedateien mit -ot/-oh werden relativ zum Laufverzeichnis angelegt.

```sh
ls -lt /data/runs
cat /data/runs/<Lauf-ID>/status.json
cat /data/runs/<Lauf-ID>/stderr.log
```

Container-Logs zeigen Start/Ende und Konfigurationsfehler, nicht absichtlich alle moeglicherweise sensiblen Fundstellen. Ein laufender Idle-Container bestaetigt keinen erfolgreichen Scan; status.json pruefen. Exit 124 bedeutet Laufzeitlimit. Nach hartem Abbruch kann ein Status auf running stehen bleiben. Keine automatische Loeschung der Ergebnisse: Volume-Groesse ueberwachen und Aufbewahrung selbst festlegen.

Bei Permission denied: Der Container arbeitet mit UID/GID 10001; das benannte Volume wird beim ersten Anlegen aus dem Image initialisiert. Bei eigenen Bind-Mounts muss das Ziel fuer 10001:10001 schreibbar sein.

Bei manifest unknown zuerst erfolgreichen GHCR-Build und Image-Tag pruefen; bei unauthorized Package-Sichtbarkeit oder Portainer-Registry-Login pruefen. Updates ueber den Repository-Stack abrufen und das Image erneut ziehen lassen.

## Sicherheit

Nur eigene Systeme oder explizit schriftlich freigegebene Ziele pruefen. Zielangaben ersetzen keine Scope-Freigabe; Cariddis Crawling-/Redirect-Verhalten ist keine Netzwerk-Sicherheitsgrenze. Fuer strikte Scopes ausgehenden Netzwerkzugriff zusaetzlich per Firewall begrenzen. Keine privilegierten Container, keine Host-Netzwerke, keine eingehenden Ports. Ergebnisse koennen Zugangsdaten und personenbezogene Daten enthalten: Zugriff beschraenken, nicht committen, Backups schuetzen. Keine Zugangsdaten in CARIDDI_TARGETS hinterlegen.
