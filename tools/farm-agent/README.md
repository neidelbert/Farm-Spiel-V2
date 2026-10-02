# Farm-Agent V2.1

Version `1.0.0-v2.1`.

Der Farm-Agent ist ein deterministischer Installer/Validator für `neidelbert/Farm-Spiel-V2`.
Er trifft keine kreativen Produktentscheidungen und schreibt normale FS-Tickets ausschließlich non-force nach `develop`.

## Sicherheitsmodell

- `main` enthält den vertrauenswürdigen Agenten und die Workflows.
- Normale FS-Tickets dürfen `.github/**`, `tools/farm-agent/**` und `.git/**` niemals ändern.
- Phase A besitzt nur Leserechte auf Repository-Inhalte.
- Phase A klont `develop` frisch, prüft Envelope, Bundle-Hash, Teil-Hashes, Base-SHA, Scopes, Pre-/Post-Hashes und die exakte Changed-File-Menge.
- Tests laufen in einer wegwerfbaren Kopie. Node-Projektskripte laufen in einem Docker-Container ohne Netzwerk.
- `npm ci` läuft nur in der Wegwerfumgebung, mit deaktivierten Install-Skripten.
- Phase B startet frisch, führt keine Tests und keinen User-Code mehr aus, prüft Bundle und Remote-SHA erneut und pusht ausschließlich non-force nach `develop`.
- Ein Job-Concurrency-Lock verhindert parallele Publish-Schreibvorgänge.
- Gleiche `requestId` + gleicher Bundle-Hash => `REUSE`, kein Doppelcommit.
- Gleiche `requestId` + anderer Bundle-Hash => `REQUEST_ID_CONFLICT`.
- Wenn `develop` nach Phase A weitergelaufen ist => `REMOTE_MOVED`.

## Ticketformat

Ausführbare Dateien heißen `.farmticket.json`.

Top-Level:
- `format = farm-ticket-v2`
- `ticket = FS-###`
- `action = INSTALL | CLOSE`
- `repository = neidelbert/Farm-Spiel-V2`
- `targetBranch = develop`
- `baseSha = 40-stelliger SHA`
- `changeType`
- `requestId`
- `payloadEncoding = gzip+base64url`
- `payloadLength`
- `payloadSha256` = SHA-256 der komprimierten Payload-Bytes
- `transport = INLINE | MULTIPART`
- `payloadPartSha256[]` = SHA-256 des ASCII-Inhalts jedes Parts
- `payloadParts[]` bei INLINE; bei MULTIPART werden die Parts separat gestaged

Der interne gzip-Payload enthält Manifest-Schema 2 mit:
- Ticket/Action/Repo/Branch/Base-SHA
- Commit-Nachricht
- Change Type
- erlaubte Scopes
- Dateioperationen (`write`, `edit`, `delete`)
- Pre-/Post-SHA-256
- erwartete geänderte Dateien
- Validatoren
- Tests
- bei CLOSE zusätzlich `reviewTargetSha`, das exakt dem echten Implementierungs-SHA entsprechen muss

## Workflows

- `Farm-Agent` – INLINE INSTALL/CLOSE
- `Farm-Agent Multipart Stage` – speichert einen geprüften Part für maximal 1 Tag
- `Farm-Agent Multipart Finalize` – setzt Parts zusammen und nutzt denselben Zwei-Phasen-Ablauf
- `Farm-Agent Selftest` – Unit-Tests + interne Sicherheitschecks
- `Farm-Agent Diagnostics` – lesender Status

## Unterstützte Validatoren

`git-diff-check`, `json-parse`, `python-compile`, `npm-typecheck`, `npm-build`,
`registry-validator`, `map-validator`, `collision-validator`, `navigation-validator`.

Unterstützte Tests: `npm-test`.

NPM-Validatoren/Testnamen sind fest auf definierte `package.json`-Scripts gemappt; Tickets dürfen keine beliebigen Shell-Kommandos an den Agenten übergeben.

## Multipart

Maximal 512 Parts, jeweils maximal 48.000 Zeichen. Jeder Part trägt:
`requestId`, `partIndex`, `partCount`, `partSha256`, `bundleSha256`.

Der Finalizer lädt nur Artefakte mit exakt passendem Namen/Metadaten, prüft jeden Part erneut und prüft danach den Gesamt-Bundle-Hash.

## Fehlercodes (Auszug)

`BASE_SHA_MISMATCH`, `REMOTE_MOVED`, `BUNDLE_HASH_MISMATCH`, `PART_HASH_MISMATCH`,
`REQUEST_ID_CONFLICT`, `PATH_TRAVERSAL`, `SYMLINK_ESCAPE`, `PROTECTED_PATH`,
`SCOPE_VIOLATION`, `PRE_HASH_MISMATCH`, `POST_HASH_MISMATCH`,
`UNEXPECTED_CHANGED_FILE`, `TEST_ISOLATION_UNAVAILABLE`, `PUSH_FAILED`.

## Vertrauensgrenze

Agent/Workflow-Änderungen sind keine normalen FS-Tickets. Sie laufen nur als separater,
vom Owner gestarteter Trusted-TOOLS-Upgrade. Der Agent darf sich selbst nicht verändern.
