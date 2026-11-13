/*
 * SinusChat — serwer
 * Copyright © 2026 Sinusoide Technology
 *
 * Ten program jest wolnym oprogramowaniem na licencji GNU Affero General Public
 * License w wersji 3 (AGPL-3.0), z tymi samymi warunkami dodatkowymi z sekcji 7
 * co aplikacja SinusChat:
 *  - licencja nie daje praw do nazw „SinusChat", „Sinia" i „Sinusoide" ani do logo;
 *    zmieniona wersja musi mieć własną nazwę (7 e),
 *  - zmieniona wersja musi być wyraźnie opisana jako zmieniona i niepochodząca
 *    od Sinusoide Technology i nie może być przedstawiana jako oficjalny serwer
 *    SinusChat (7 c),
 *  - trzeba zachować informacje o prawach autorskich i autorach (7 b),
 *  - nie wolno używać nazwy Sinusoide Technology do reklamowania zmienionych
 *    wersji ani sugerować, że je popieramy (7 d).
 *
 * Jeśli udostępniasz zmieniony serwer innym przez sieć, musisz im udostępnić jego
 * kod źródłowy (sekcja 13 AGPL-3.0). Program jest rozpowszechniany BEZ ŻADNEJ
 * GWARANCJI. Pełny tekst licencji: LICENSE i NOTICE.md, opis po polsku:
 * https://sinusoide.pl/dokumentacja.html
 *
 * English: free software under the GNU Affero General Public License version 3
 * with the same additional terms under section 7 as the SinusChat app (names and
 * marks, marking modified versions, authorship, endorsement), see NOTICE.md.
 * No warranty.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

"use strict";

const { PORT, HOST } = require("./src/config");
const { buildApp } = require("./src/app");
const { migrateBlockTags } = require("./src/blocks");
const { db, ensureSchema, migrateAvatarNames } = require("./src/db");
const { startJobs } = require("./src/jobs");

const app = buildApp();

const schemaReady = ensureSchema().then(migrateAvatarNames).then(migrateBlockTags);
startJobs(schemaReady);

schemaReady.finally(() => {
  app.listen({ port: PORT, host: HOST }, (err) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    console.log(`SinusChat server running on ${HOST}:${PORT}`);
  });
});

let shuttingDown = false;
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`${signal} received, shutting down`);
    setTimeout(() => process.exit(1), 10_000).unref();
    app
      .close()
      .then(() => db.end())
      .then(
        () => process.exit(0),
        () => process.exit(1),
      );
  });
}
