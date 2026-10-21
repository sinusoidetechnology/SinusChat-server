# SinusChat — serwer

Serwer komunikatora [SinusChat](https://sinusoide.pl): API i WebSocket (Fastify) z bazą PostgreSQL. Przekazuje zaszyfrowane wiadomości, sygnalizację połączeń i sygnały budzące telefon. Treści wiadomości nie zna, bo szyfrują je telefony (protokół Signal).

Licencja: AGPL-3.0 z warunkami dodatkowymi, opisanymi w [NOTICE.md](NOTICE.md). Błędy bezpieczeństwa zgłaszaj według [SECURITY.md](SECURITY.md).

## Co jest potrzebne

- Node.js 20 lub nowszy
- PostgreSQL 17 lub nowszy
- nginx przed serwerem: serwer słucha tylko na `127.0.0.1`, a nginx musi ustawiać nagłówek `X-Real-IP` (od niego zależą limity i lista IP panelu zgłoszeń)
- coturn z `use-auth-secret` i tym samym sekretem co `TURN_SECRET`
- serwer plików PHP (`auth.php`, `upload.php`), z którym serwer dzieli sekrety `AUTH_PROOF_SECRET` i `UPLOAD_TOKEN_SECRET`
- opcjonalnie własny ntfy i konto usługi Firebase

Serwer trzyma stan rozmów i obecności w pamięci, więc działa jako jedna instancja. Głosówki zapisuje w `/opt/sinuschat/uploads/voice`. Adres serwera plików (`files.sinusoide.pl`) jest wpisany w kodzie: przy własnej instalacji trzeba go zmienić.

## Uruchomienie

```bash
npm install
psql "$DATABASE_URL" -f schema.sql
node server.js
```

Przy starcie serwer sam dopisuje brakujące kolumny i tabele. Zmienne środowiskowe ustaw w usłudze systemd albo w pliku `.env` (wzór: [.env.example](.env.example)). Nie dodawaj prawdziwych wartości do repozytorium.

## Zmienne środowiskowe

| Zmienna | Wymagana | Do czego służy |
|---|---|---|
| `DATABASE_URL` | tak | adres bazy PostgreSQL |
| `JWT_SECRET` | tak | podpis tokenów sesji |
| `TURN_SECRET` | tak | wspólny sekret z coturn; z niego powstają godzinne hasła TURN |
| `UPLOAD_TOKEN_SECRET` | tak | wspólny z `upload.php`: tokeny wysyłki plików, podpis przekaźnika dla Tora, kasowanie zdjęć profilowych |
| `AUTH_PROOF_SECRET` | tak | wspólny z `auth.php`: kody z e-maila i dowody logowania; bez niego rejestracja i logowanie są zablokowane |
| `REQUIRE_AUTH_PROOF` | nie (domyślnie `1`) | `0` wyłącza wymóg potwierdzenia e-maila, tylko do testów |
| `PORT` | nie (domyślnie `3000`) | port na `127.0.0.1` |
| `PUBLIC_API_URL` | nie | publiczny adres API, używany w linkach do głosówek |
| `TURN_HOST` | nie | nazwa serwera TURN podawana aplikacji |
| `NTFY_URL` | nie (domyślnie `https://ntfy.sh`) | serwer ntfy budzący telefony bez usług Google |
| `FCM_SERVICE_ACCOUNT_FILE` | nie | ścieżka do pliku konta usługi Firebase; bez niego działa tylko ntfy |
| `REPORTS_ADMIN_KEY` | nie | klucz panelu zgłoszeń, co najmniej 24 znaki; bez niego panel jest wyłączony |
| `REPORTS_ADMIN_IPS` | nie | adresy IP oddzielone przecinkami, z których wolno wejść do panelu zgłoszeń |

## English

The SinusChat messenger server: a Fastify API and WebSocket with PostgreSQL. It relays end-to-end encrypted messages, call signalling and wake-up pushes; message contents are encrypted on the phones. It needs Node.js 20+, PostgreSQL 17+, nginx in front (setting `X-Real-IP`), coturn sharing `TURN_SECRET`, and the PHP file server sharing `AUTH_PROOF_SECRET` and `UPLOAD_TOKEN_SECRET`. Environment variables are listed in the table above and in [.env.example](.env.example). Licensed under AGPL-3.0 with additional terms, see [NOTICE.md](NOTICE.md).
