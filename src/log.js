// SinusChat — serwer. Copyright © 2026 Sinusoide Technology. SPDX-License-Identifier: AGPL-3.0-only

"use strict";

// Komunikaty błędów (zwłaszcza z PostgreSQL) potrafią zawierać wartości z zapytań: hashe kont,
// adresy e-mail i IP. Do logów trafia tylko wersja z zamaskowanymi danymi, przycięta do 300 znaków.
function scrubLog(text) {
  return String(text || "")
    .replace(/[^\s@]+@[^\s@]+/g, "<email>")
    .replace(/[0-9a-f]{16,}/gi, "<id>")
    .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, "<ip>")
    .slice(0, 300);
}

module.exports = { scrubLog };
