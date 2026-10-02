# Farm-Spiel Agent – iPhone Control Center Contract

Der iPhone-Kurzbefehl darf GitHub-Inhalte nicht direkt schreiben.

Token-Zielrechte:
- Actions: Read and write
- Contents: Read-only
- Metadata: Read-only

## INLINE
1. `.farmticket.json` lesen.
2. `format`, `repository`, `targetBranch`, `ticket`, `action`, `transport` prüfen.
3. Bei `transport=INLINE` den kompletten JSON-Text als Input `ticket_json` an
   `.github/workflows/farm-agent.yml` dispatchen.
4. Run suchen/pollen.
5. Bei PASS kurze Mitteilung; bei FAIL Run öffnen.

## MULTIPART
1. Header aus der Ticketdatei bilden: alles behalten, aber `payloadParts` entfernen.
2. Jeden Part einzeln an `.github/workflows/farm-agent-stage.yml` senden:
   `request_id`, `part_index`, `part_count`, `part_sha256`, `bundle_sha256`, `part_data`.
3. Erst wenn alle Stage-Runs PASS sind, `ticket_header_json` an
   `.github/workflows/farm-agent-multipart.yml` senden.
4. Final-Run pollen.

## Hauptmenü
- Ticket installieren
- Ticket schließen
- Owner-Befehl (bis Owner-Core: „Noch nicht verfügbar“)
- Projektstatus
- Tests starten
- Letzten Run öffnen
- Agent-Selbsttest

Der Kurzbefehl verändert den Payload niemals und fügt keinen zusätzlichen Base64-Schritt hinzu.
