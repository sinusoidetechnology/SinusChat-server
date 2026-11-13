// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

function requiredEnv(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`[FATAL] Brak zmiennej środowiskowej ${name} — nie startuję.`);
    process.exit(1);
  }
  return v;
}

const PORT = process.env.PORT || 3000;
// Domyślnie tylko pętla zwrotna (nginx na tym samym hoście). W kontenerze Docker
// ustawiane na 0.0.0.0, a port publikowany jest wyłącznie na 127.0.0.1 hosta.
const HOST = process.env.HOST || "127.0.0.1";
const DB_URL = requiredEnv("DATABASE_URL");
const JWT_SECRET = requiredEnv("JWT_SECRET");
const TURN_SECRET = requiredEnv("TURN_SECRET");
const UPLOAD_TOKEN_SECRET = requiredEnv("UPLOAD_TOKEN_SECRET");
const NTFY_BASE = process.env.NTFY_URL || "https://ntfy.sh";
const TURN_HOST = process.env.TURN_HOST || "turn.sinusoide.pl";

const FCM_SERVICE_ACCOUNT_FILE = process.env.FCM_SERVICE_ACCOUNT_FILE || "";

const AUTH_PROOF_SECRET = process.env.AUTH_PROOF_SECRET || null;
const REQUIRE_AUTH_PROOF = process.env.REQUIRE_AUTH_PROOF !== "0";

// Klucz HMAC, którym zapisywane są blokady (blocked_users). Brak = blokady jawne w bazie.
// Raz ustawionego nie wolno zmieniać ani usuwać: serwer nie odczyta wtedy istniejących blokad.
const BLOCK_SECRET = process.env.BLOCK_SECRET || null;

const MIN_SECRET_CHARS = 32;
for (const [name, secret] of Object.entries({ JWT_SECRET, TURN_SECRET, UPLOAD_TOKEN_SECRET, AUTH_PROOF_SECRET, BLOCK_SECRET })) {
  if (secret && secret.length < MIN_SECRET_CHARS) {
    console.warn(`[UWAGA] ${name} ma mniej niż ${MIN_SECRET_CHARS} znaki: użyj losowej wartości, np. openssl rand -hex 32.`);
  }
}

if (!AUTH_PROOF_SECRET) {
  console.error("[UWAGA] Brak AUTH_PROOF_SECRET — rejestracja i logowanie są ZABLOKOWANE, dopóki go nie ustawisz.");
} else if (!REQUIRE_AUTH_PROOF) {
  console.warn("[UWAGA] REQUIRE_AUTH_PROOF=0 — rejestracja bez dowodu z kodu e-mail jest przyjmowana. " + "Ustaw 1 albo usuń zmienną.");
}

const REPORTS_ADMIN_KEY = process.env.REPORTS_ADMIN_KEY || null;

const REPORTS_ADMIN_IPS = (process.env.REPORTS_ADMIN_IPS || "")
  .split(",")
  .map((x) => x.trim())
  .filter(Boolean);

if (!REPORTS_ADMIN_KEY || REPORTS_ADMIN_KEY.length < 24) {
  console.warn("[UWAGA] Brak REPORTS_ADMIN_KEY (min. 24 znaki) — panel zgłoszeń /api/reports-admin jest wyłączony. " + "Zgłoszenia z aplikacji i tak się zapisują.");
}

module.exports = {
  PORT,
  HOST,
  DB_URL,
  JWT_SECRET,
  TURN_SECRET,
  UPLOAD_TOKEN_SECRET,
  NTFY_BASE,
  TURN_HOST,
  FCM_SERVICE_ACCOUNT_FILE,
  AUTH_PROOF_SECRET,
  REQUIRE_AUTH_PROOF,
  BLOCK_SECRET,
  REPORTS_ADMIN_KEY,
  REPORTS_ADMIN_IPS,
};
