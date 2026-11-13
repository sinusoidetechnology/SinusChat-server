# SinusChat — Serwer API i WebSocket

Oficjalny backend komunikatora **[SinusChat](https://sinusoide.pl)** — wysokowydajny serwer API oraz WebSocket oparty na **Fastify (Node.js)** i bazie danych **PostgreSQL**.

Serwer odpowiada za przekazywanie zaszyfrowanych wiadomości end-to-end (E2EE), dystrybucję kluczy kryptograficznych (protokół Signal z rozszerzeniem post-kwantowym Kyber / PQXDH), obsługę wiadomości Sealed Sender, sygnalizację połączeń głosowych i wideo (1-na-1 oraz grupowych WebRTC) oraz wybudzanie urządzeń mobilnych (ntfy / Firebase Cloud Messaging). **Serwer działa w modelu zero-knowledge wobec treści rozmów** — nie posiada kluczy prywatnych i nie ma możliwości odszyfrowania przesyłanych wiadomości ani rozmów.

---

## Spis treści

1. [Architektura i możliwości backendu](#1-architektura-i-możliwości-backendu)
2. [Wymagania systemowe i infrastruktura](#2-wymagania-systemowe-i-infrastruktura)
3. [Struktura projektu](#3-struktura-projektu)
4. [Zmienne środowiskowe (`.env`)](#4-zmienne-środowiskowe-env)
5. [Uruchamianie serwera](#5-uruchamianie-serwera)
   - [Opcja A: Docker i Docker Compose (zalecana)](#opcja-a-docker-i-docker-compose-zalecana)
   - [Opcja B: Usługa systemd na hoście (z utwardzeniem)](#opcja-b-usługa-systemd-na-hoście-z-utwardzeniem)
   - [Opcja C: Uruchomienie bezpośrednie (Node.js / obecny tryb ręczny)](#opcja-c-uruchomienie-bezpośrednie-nodejs--obecny-tryb-ręczny)
6. [Migracja bazy danych PostgreSQL z hosta do Dockera](#6-migracja-bazy-danych-postgresql-z-hosta-do-dockera)
7. [Zadania okresowe i utrzymanie ruchu](#7-zadania-okresowe-i-utrzymanie-ruchu)
8. [Bezpieczeństwo i zgłaszanie podatności](#8-bezpieczeństwo-i-zgłaszanie-podatności)
9. [Licencja](#9-licencja)
10. [English Summary](#10-english-summary)

---

## 1. Architektura i możliwości backendu

- **Szyfrowanie End-to-End (Protokół Signal + Kyber):** Przechowywanie i dystrybucja kluczy tożsamości (`identity_key`), podpisanych pre-kluczy (`signed_prekey`), jednorazowych pre-kluczy (`signal_prekeys`) oraz post-kwantowych kluczy Kyber (`kyber_prekey`). Powiadamianie kontaktów o zmianie klucza bezpieczeństwa (`peer_key`).
- **Wiadomości i Sealed Sender:** Kolejkowanie zaszyfrowanych ładunków (`bytea`) dla odbiorców offline, obsługa potwierdzeń dostarczenia/odczytu (`ack`), wiadomości znikających (`disappearing_ttl_ms`) oraz anonimowego nadawcy (_Sealed Sender_ z kontrolą budżetu i ochroną przed floodem; `urgent: false` oznacza cichą ramkę bez pilnego pusha).
- **Potwierdzane dostarczanie:** Ramka wysłana przez WebSocket uznawana jest za dostarczoną dopiero po pongu na ping wysłany zaraz po niej. Bez potwierdzenia w ciągu **15 s** wiadomość wraca do kolejki, a telefon jest budzony. Pobranie kolejki z `GET /api/messages/pending?confirm=1` działa jak dzierżawa: wiadomości niepotwierdzone przez `POST /api/messages/received` w ciągu **60 s** wracają do kolejki.
- **Komunikacja czasu rzeczywistego (WebSocket):** Natychmiastowe przekazywanie wiadomości, statusów pisania (`typing`), obecności (`presence`) oraz pełnej sygnalizacji połączeń WebRTC (`call_offer`, `call_answer`, `call_ice`, `call_screen` oraz grupowych `gcall_*`).
- **Grupy i społeczności:** Tworzenie grup i kanałów społecznościowych (do 1000 członków), uprawnienia administracyjne (`perms`), linki zaproszeniowe (`grp_...`), bany grupowe oraz zaszyfrowane awatary.
- **Konta e-mail i anonimowe:** Uwierzytelnianie z dowodem kryptograficznym (`AUTH_PROOF_SECRET`) lub za pomocą podpisu Ed25519 i wyzwania Proof-of-Work (20 bitów) dla kont anonimowych. Kontrola pojedynczego aktywnego urządzenia (`active_device_id`) i sesje JWT.
- **Przekaźnik plików (Tor / Privacy Relay):** Wbudowany przekaźnik `/api/files/*` do zewnętrznego serwera plików PHP (`files.sinusoide.pl`), umożliwiający pobieranie/wysyłanie załączników (w tym głosówek), awatarów i modeli tłumaczeń bez bezpośredniego łączenia klienta z serwerem plików (np. przez sieć Tor). Sam serwer API nie zapisuje żadnych plików na dysku.
- **Prywatność blokad i obecności:** Blokady w tabeli `blocked_users` są zapisywane jako HMAC (`BLOCK_SECRET`), więc zrzut bazy nie zdradza, kto kogo zablokował. Status obecności widzą tylko osoby znające klucz dostępu danego konta lub należące z nim do wspólnej grupy.
- **Powiadomienia Push (Wake-up):** Wybudzanie telefonów bez zdradzania treści wiadomości — domyślnie przez **ntfy** (dla urządzeń bez usług Google, np. GrapheneOS) oraz opcjonalnie przez **Firebase Cloud Messaging (FCM)**.
- **Ochrona przed nadużyciami (Rate Limiting & Budgets):** Limity zapytań HTTP per konto (`600/min`) oraz per IP (`300/min`), budżety transferu dla wiadomości i pakietów Sealed Sender oraz limity zapytań o klucze i wyszukiwarkę.

> [!IMPORTANT]
> Serwer przechowuje w pamięci RAM aktywne połączenia WebSocket, stan rozmów grupowych, bufory obecności oraz liczniki limitów (rate-limit / budżety). Z tego powodu **musi działać jako pojedyncza instancja** (single-instance).

---

## 2. Wymagania systemowe i infrastruktura

Do pełnego działania środowiska produkcyjnego wymagane są:

1. **Środowisko uruchomieniowe:**
   - **Docker Engine** z **Docker Compose v2.24+** (zalecane), _lub_
   - **Node.js 20+** (zalecany **Node.js 24 LTS**) oraz **PostgreSQL 17/18+** bezpośrednio na hoście.
2. **Reverse Proxy (nginx):**
   - Serwer nasłuchuje wyłącznie na pętli zwrotnej (`127.0.0.1`). Przed nim **musi** stać `nginx` obsługujący TLS (HTTPS/WSS) i nadpisujący nagłówek `X-Real-IP`:
     ```nginx
     proxy_set_header X-Real-IP $remote_addr;
     proxy_set_header Host $host;
     proxy_http_version 1.1;
     proxy_set_header Upgrade $http_upgrade;
     proxy_set_header Connection "upgrade";
     ```
   - > [!WARNING]
     > Serwer bezwarunkowo ufa nagłówkowi `X-Real-IP`. Nigdy nie wystawiaj portu serwera bezpośrednio na `0.0.0.0` z pominięciem nginx — pozwoliłoby to na fałszowanie adresów IP i obejście limitów zapytań oraz blokad IP panelu administracyjnego.
3. **Serwer TURN (`coturn`):**
   - Skonfigurowany z opcją `use-auth-secret` oraz wspólnym sekretem `TURN_SECRET` (do generowania tymczasowych poświadczeń WebRTC metodą HMAC-SHA1).
4. **Zewnętrzny serwer plików PHP (`auth.php`, `upload.php`):**
   - Współdzielący z backendem sekrety `AUTH_PROOF_SECRET` oraz `UPLOAD_TOKEN_SECRET`. Domyślny adres (`files.sinusoide.pl`) jest zdefiniowany w `src/routes/media.js`, `src/routes/users.js` i `src/routes/groups.js` — przy własnym wdrożeniu należy go dostosować.
5. **Powiadomienia (opcjonalnie):**
   - Własna instancja **ntfy** (domyślnie używany jest `https://ntfy.sh`) oraz plik konta usługi **Firebase (`fcm.json`)** dla urządzeń korzystających z FCM.

---

## 3. Struktura projektu

```text
SinusChat-server/
├── server.js                  # Punkt wejścia: inicjalizacja schematu DB, zadań cyklicznych, start Fastify i graceful shutdown
├── schema.sql                 # Pełny schemat bazy danych PostgreSQL (tabele, sekwencje, klucze główne, indeksy)
├── package.json               # Zależności projektu (fastify, pg, jsonwebtoken, @fastify/websocket, @fastify/rate-limit)
├── Dockerfile                 # Wieloetapowy, utwardzony obraz produkcyjny (node:24-alpine + tini, bez npm/yarn)
├── docker-compose.yaml        # Konfiguracja kontenerów: serwer API (`server`) oraz baza PostgreSQL 18 (`postgres`)
├── .env.example               # Szablon zmiennych środowiskowych
├── LICENSE                    # Pełny tekst licencji GNU AGPLv3
├── NOTICE.md                  # Dodatkowe warunki licencyjne (sekcja 7 AGPL-3.0) i informacje o znakach towarowych
├── SECURITY.md                # Polityka odpowiedzialnego zgłaszania luk bezpieczeństwa (Responsible Disclosure)
├── deploy/
│   └── sinuschat.service      # Utwardzona jednostka systemd do uruchomienia serwera bezpośrednio na hoście
├── db_data/                   # Wolumen danych bazy PostgreSQL (tworzony i używany przez Docker Compose)
└── src/
    ├── config.js              # Wczytywanie, walidacja i wartości domyślne zmiennych środowiskowych
    ├── app.js                 # Konfiguracja instancji Fastify: wtyczki, limity zapytań, nagłówki bezpieczeństwa (HSTS, CSP), rejestracja tras
    ├── db.js                  # Pula połączeń PostgreSQL (`pg.Pool`), automatyczne migracje przy starcie (`ensureSchema`) i migracje awatarów
    ├── crypto.js              # Centralny moduł kryptograficzny: SHA-256, HMAC, Ed25519, RSA-SHA256, poświadczenia TURN, timingSafeEqual
    ├── blocks.js              # Blokady zapisywane jako HMAC (`BLOCK_SECRET`) i jednorazowa migracja jawnych wierszy (`migrateBlockTags`)
    ├── log.js                 # `scrubLog`: maskowanie e-maili, hashy i adresów IP w logach błędów
    ├── common.js              # Współdzielone funkcje pomocnicze: gniazda WebSocket, potwierdzanie dostarczenia (ping/pong), budżety, limity, uprawnienia konwersacji i grup
    ├── jobs.js                # Zadania okresowe (cron w procesie): czyszczenie wygasłych i dostarczonych wiadomości, zaproszeń, zgłoszeń, nieaktywnych kont i kontrola dysku
    └── routes/
        ├── auth.js            # Logowanie, rejestracja, weryfikacja dowodów e-mail/anon (PoW + Ed25519), middleware `requireAuth` (JWT)
        ├── users.js           # Profile użytkowników, klucze dostępu, blokowanie, wyszukiwanie, ustawienia prywatności, planowanie usunięcia konta
        ├── signal.js          # Zarządzanie kluczami protokołu Signal (Identity, Signed PreKey, One-Time PreKeys, Kyber PreKey)
        ├── messages.js        # Wysyłanie i odbieranie wiadomości, kolejka offline, potwierdzenia `ack`, obsługa pakietów Sealed Sender
        ├── conversations.js   # Pobieranie listy konwersacji, ustawienia znikających wiadomości (TTL), usuwanie i wyciszanie rozmów
        ├── groups.js          # Tworzenie i edycja grup/społeczności, członkowie, uprawnienia adminów, kody zaproszeń (`grp_...`), bany
        ├── invites.js         # Zaproszenia do kontaktów jednorazowe (`once`) i wielokrotne (`multi`) (`inv_...`)
        ├── calls.js           # Poświadczenia TURN (`/api/turn-credentials`), stan i sygnalizacja połączeń 1-na-1 oraz grupowych (`gcall`)
        ├── presence.js        # Statusy aktywności (`heartbeat`, `last_seen_ms`), śledzenie dziennej aktywności kont i grup
        ├── push.js            # Konfiguracja i wysyłka cichych powiadomień budzących przez ntfy oraz Firebase Cloud Messaging (FCM)
        ├── media.js           # Tokeny wysyłki (`/api/upload-token`) i przekaźnik `/api/files/*` do serwera plików
        ├── reports.js         # Przyjmowanie zgłoszeń błędów z aplikacji oraz chroniony panel administracyjny (`/api/reports-admin`)
        └── ws.js              # Serwer WebSocket (`/ws`): autoryzacja sesji, obsługa ramek czasu rzeczywistego, keep-alive (ping/pong)
```

---

## 4. Zmienne środowiskowe (`.env`)

Skopiuj plik przykładowy i zabezpiecz uprawnienia:

```bash
cp .env.example .env
chmod 600 .env
```

> [!TIP]
> W pliku `.env` zapisuj wartości w formacie `KLUCZ=wartość` **bez cudzysłowów** — dzięki temu plik jest identycznie interpretowany przez Docker Compose, `EnvironmentFile` w systemd oraz powłokę bash.
> Wszystkie sekrety kryptograficzne powinny mieć minimum **32 znaki** (wygenerujesz je poleceniem `openssl rand -hex 32`).

### Zmienne aplikacji (`src/config.js`)

| Zmienna                    | Wymagana  | Domyślnie                  | Opis                                                                                                                                                                                                                 |
| :------------------------- | :-------: | :------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`             |  **Tak**  | —                          | Pełny URI połączenia z bazą PostgreSQL, np. `postgres://sinuschat:HASLO@postgres:5432/sinuschat` (w Dockerze) lub `postgres://sinuschat:HASLO@127.0.0.1:5432/sinuschat` (na hoście).                                 |
| `JWT_SECRET`               |  **Tak**  | —                          | Sekret (min. 32 znaki) do podpisywania i weryfikacji tokenów sesji JWT (HS256, ważność 30 dni).                                                                                                                      |
| `TURN_SECRET`              |  **Tak**  | —                          | Wspólny sekret z serwerem `coturn` (`use-auth-secret`), używany do wyliczania tymczasowych haseł TURN.                                                                                                               |
| `UPLOAD_TOKEN_SECRET`      |  **Tak**  | —                          | Wspólny sekret z `upload.php` na serwerze plików: podpisywanie tokenów wysyłki, autoryzacja przekaźnika `/api/files/*`, kasowanie i skracanie nazw awatarów.                                                         |
| `AUTH_PROOF_SECRET`        | **Tak\*** | `null`                     | Wspólny sekret z `auth.php` służący do weryfikacji kodów e-mail i dowodów logowania. **Bez tej zmiennej rejestracja i logowanie są całkowicie zablokowane.**                                                         |
| `REQUIRE_AUTH_PROOF`       |    Nie    | `1`                        | Gdy ustawione na `0`, wyłącza wymóg potwierdzenia kodu e-mail przy rejestracji (wyłącznie do lokalnych testów!).                                                                                                     |
| `BLOCK_SECRET`             | Zalecana  | `null`                     | Klucz HMAC (min. 32 znaki), którym zapisywane są blokady w `blocked_users`. Przy pierwszym starcie z tą zmienną istniejące jawne blokady są jednorazowo zaszyfrowane. **Raz ustawionego nie wolno zmieniać ani usuwać** — bez niego serwer odmówi startu, a po zmianie straci istniejące blokady. Bez zmiennej blokady leżą w bazie jawnie. |
| `HOST`                     |    Nie    | `127.0.0.1`                | Adres interfejsu, na którym nasłuchuje Fastify. Na hoście zostaw `127.0.0.1`; w kontenerze Docker Compose nadpisuje go wewnątrz na `0.0.0.0`.                                                                        |
| `PORT`                     |    Nie    | `3000`                     | Port nasłuchu serwera HTTP/WebSocket. W Docker Compose określa również port wystawiany na `127.0.0.1` hosta.                                                                                                         |
| `TURN_HOST`                |    Nie    | `turn.sinusoide.pl`        | Domena lub adres IP serwera TURN przekazywany klientom w `/api/turn-credentials`.                                                                                                                                    |
| `NTFY_URL`                 |    Nie    | `https://ntfy.sh`          | Bazowy adres serwera `ntfy` do wysyłania powiadomień budzących (wake-up push).                                                                                                                                       |
| `FCM_SERVICE_ACCOUNT_FILE` |    Nie    | `""`                       | Ścieżka do pliku JSON konta usługi Firebase. Jeśli pusta, serwer budzi urządzenia wyłącznie przez `ntfy`.                                                                                                            |
| `REPORTS_ADMIN_KEY`        |    Nie    | `null`                     | Klucz dostępu (min. 24 znaki, przekazywany w nagłówku `x-admin-key`) do panelu administracyjnego zgłoszeń `/api/reports-admin`. Jeśli brak lub za krótki, panel jest wyłączony (same zgłoszenia nadal się zapisują). |
| `REPORTS_ADMIN_IPS`        |    Nie    | `""`                       | Lista dozwolonych adresów IP (oddzielonych przecinkami) uprawnionych do odpytywania `/api/reports-admin`. Gdy pusta, dostęp chroni sam klucz `REPORTS_ADMIN_KEY`.                                                    |

### Zmienne specyficzne dla Docker Compose (`docker-compose.yaml`)

| Zmienna               | Wymagana w Dockerze | Domyślnie   | Opis                                                                                                |
| :-------------------- | :-----------------: | :---------- | :-------------------------------------------------------------------------------------------------- |
| `POSTGRES_USER`       |         Nie         | `sinuschat` | Nazwa użytkownika tworzonego w kontenerze PostgreSQL oraz używana przez healthcheck.                |
| `POSTGRES_DB`         |         Nie         | `sinuschat` | Nazwa bazy danych tworzonej w kontenerze PostgreSQL.                                                |
| `POSTGRES_PASSWORD`   |       **Tak**       | —           | Hasło użytkownika bazy danych w kontenerze `postgres`. Musi pokrywać się z hasłem w `DATABASE_URL`. |
| `SINUSCHAT_UID`       |         Nie         | `1000`      | UID użytkownika, jako który działa proces Node.js w kontenerze.                                     |
| `SINUSCHAT_GID`       |         Nie         | `1000`      | GID grupy, jako która działa proces Node.js w kontenerze.                                           |
| `SINUSCHAT_IMAGE_TAG` |         Nie         | `latest`    | Tag budowanego obrazu Docker (`sinuschat-server:<tag>`).                                            |

---

## 5. Uruchamianie serwera

Przy każdym starcie (`server.js`) backend automatycznie wywołuje `ensureSchema()`, `migrateAvatarNames()` oraz `migrateBlockTags()`, dzięki czemu sam dopisuje ewentualne brakujące kolumny, tabele i indeksy w istniejącej bazie danych, a po ustawieniu `BLOCK_SECRET` jednorazowo szyfruje istniejące blokady. Serwer zaczyna przyjmować połączenia dopiero po tych krokach.

### Opcja A: Docker i Docker Compose (zalecana)

Konfiguracja w `Dockerfile` oraz `docker-compose.yaml` uruchamia cały stos (serwer API + PostgreSQL 18) w odizolowanych kontenerach z utwardzeniem bezpieczeństwa:

- Obraz bazuje na `node:24-alpine`, procesem PID 1 jest `tini`, a menedżery pakietów (`npm`, `npx`, `yarn`, `corepack`) są usunięte z obrazu uruchomieniowego.
- Proces serwera działa jako nieuprzywilejowany użytkownik (`1000:1000`), system plików kontenera jest w trybie **tylko do odczytu (`read_only: true`)**, a zapis możliwy jest wyłącznie do pamięciowego `/tmp` (`tmpfs`) — serwer nie przechowuje plików na dysku.
- Włączona jest flaga `no-new-privileges:true`, rotacja logów (`max-size: 10m`, `max-file: 5`) oraz wbudowany `HEALTHCHECK` odpytujący `/health`.
- Kontener bazy danych `postgres:18-alpine` działa w wewnętrznej sieci `db` (`internal: true`) bez dostępu z zewnątrz i automatycznie wykonuje `schema.sql` przy pierwszym utworzeniu wolumenu `./db_data`.
- Port API publikowany jest wyłącznie na `127.0.0.1:${PORT}:3000`.

#### Krok po kroku:

1. **Przygotuj plik `.env`:**

   ```bash
   cp .env.example .env
   chmod 600 .env
   ```

   Upewnij się, że w `.env` ustawiłeś `POSTGRES_PASSWORD` oraz wskazujesz na kontener `postgres` w `DATABASE_URL`:

   ```ini
   POSTGRES_USER=sinuschat
   POSTGRES_DB=sinuschat
   POSTGRES_PASSWORD=TwojeSilneHasloBazy
   DATABASE_URL=postgres://sinuschat:TwojeSilneHasloBazy@postgres:5432/sinuschat
   ```

2. **Przygotuj katalog na dane bazy:**

   ```bash
   mkdir -p ./db_data
   ```

3. **Zbuduj i uruchom kontenery:**

   ```bash
   docker compose up -d --build
   ```

4. **Przydatne polecenia eksploatacyjne:**
   ```bash
   docker compose ps                            # Sprawdzenie statusu kontenerów i healthchecków
   docker compose logs -f server                # Podgląd logów serwera API na żywo
   docker compose logs -f postgres              # Podgląd logów bazy PostgreSQL
   git pull && docker compose up -d --build     # Aktualizacja kodu i przebudowa obrazu
   docker compose down                          # Zatrzymanie kontenerów (dane w ./db_data zostają)
   ```

---

### Opcja B: Usługa systemd na hoście (z utwardzeniem)

Jeśli nie korzystasz z Dockera, w pliku [`deploy/sinuschat.service`](deploy/sinuschat.service) znajduje się gotowa jednostka `systemd` z restrykcyjnym sandboxingiem (`ProtectSystem=strict`, `NoNewPrivileges=yes`, brak capabilities, prywatny `/tmp`, filtr syscall `@system-service`, ukryty `/proc`).

Zakłada ona instalację kodu w `/opt/sinuschat/server`. Usługa nie ma żadnych katalogów z prawem zapisu (`ProtectSystem=strict` bez `ReadWritePaths`), bo serwer nie przechowuje plików na dysku.

```bash
# 1. Utwórz dedykowanego użytkownika systemowego bez powłoki
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sinuschat

# 2. Pobierz kod i zainstaluj zależności produkcyjne (właścicielem kodu pozostaje root)
sudo mkdir -p /opt/sinuschat
sudo git clone <adres-repozytorium> /opt/sinuschat/server
cd /opt/sinuschat/server
sudo npm ci --omit=dev

# 3. Skonfiguruj zmienne środowiskowe
sudo cp .env.example .env
sudo nano .env   # Uzupełnij DATABASE_URL (np. @127.0.0.1:5432) oraz sekrety; zostaw HOST=127.0.0.1
sudo chown root:sinuschat .env
sudo chmod 640 .env

# 4. Załaduj schemat do lokalnej bazy PostgreSQL (tylko przy nowej bazie)
set -a && sudo . ./.env && set +a
psql "$DATABASE_URL" -f schema.sql

# 5. Zainstaluj i uruchom usługę systemd
sudo cp deploy/sinuschat.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sinuschat

# 6. Sprawdź status i logi
sudo systemctl status sinuschat
journalctl -u sinuschat -f
```

> [!NOTE]
> Poziom utwardzenia usługi możesz zweryfikować poleceniem `systemd-analyze security sinuschat`.

---

### Opcja C: Uruchomienie bezpośrednie (Node.js / obecny tryb ręczny)

Do pracy deweloperskiej, szybkiego testowania lub tradycyjnego uruchomienia bezpośrednio z katalogu roboczego (bez systemd i bez Dockera) wystarczy zainstalowany lokalnie Node.js (v20+) oraz działający serwer PostgreSQL (na hoście lub wystawiony z kontenera):

```bash
# 1. Zainstaluj zależności
npm install

# 2. Przygotuj plik .env
cp .env.example .env

# 3. (Opcjonalnie) Wgraj schemat do nowej bazy danych
set -a && . ./.env && set +a
psql "$DATABASE_URL" -f schema.sql

# 4. Wczytaj zmienne z .env do bieżącej powłoki i uruchom serwer
set -a && . ./.env && set +a
npm start
# lub bezpośrednio:
node server.js
```

Serwer zweryfikuje stan schematu bazy danych (`[SCHEMA] schemat aktualny`), uruchomi zadania w tle i zacznie nasłuchiwać pod adresem wskazanym w `HOST:PORT` (domyślnie `127.0.0.1:3000`). Zatrzymanie procesu sygnałem `SIGINT` (`Ctrl+C`) lub `SIGTERM` bezpiecznie zamyka gniazda Fastify oraz pulę połączeń PostgreSQL.

---

## 6. Migracja bazy danych PostgreSQL z hosta do Dockera

Poniższa procedura pozwala bezpiecznie przenieść istniejącą bazę danych PostgreSQL działającą bezpośrednio na hoście (lub na innym serwerze) do kontenera `sinuschat-postgres` zarządzanego przez `docker-compose.yaml`, bez utraty użytkowników, kluczy Signal, grup ani kolejki wiadomości.

### Krok 1: Zatrzymaj serwer aplikacji (aby uniknąć zapisu nowych danych podczas zrzutu)

Jeśli serwer działał przez `systemd`:

```bash
sudo systemctl stop sinuschat
```

Jeśli działał ręcznie lub w Dockerze:

```bash
docker compose stop server
```

### Krok 2: Wykonaj pełny zrzut (backup) obecnej bazy z hosta

Użyj narzędzia `pg_dump` z flagami `--no-owner` oraz `--no-privileges`, aby uniknąć problemów z różnicami w nazwach ról pomiędzy hostem a kontenerem:

```bash
# Zastąp adres połączenia swoimi dotychczasowymi danymi dostępowymi do lokalnego PostgreSQL:
pg_dump "postgres://sinuschat:STARE_HASLO@127.0.0.1:5432/sinuschat" \
  --no-owner \
  --no-privileges \
  --clean \
  --if-exists \
  -f sinuschat_backup.sql
```

_(Alternatywnie, jeśli masz dostęp z konta systemowego `postgres`: `sudo -u postgres pg_dump --no-owner --no-privileges --clean --if-exists sinuschat > sinuschat_backup.sql`)._

Sprawdź, czy plik `sinuschat_backup.sql` powstał i nie jest pusty (`ls -lh sinuschat_backup.sql`).

### Krok 3: Zaktualizuj plik `.env` pod kątem Docker Compose

W pliku `.env` ustaw zmienne dla kontenera PostgreSQL oraz zmień host w `DATABASE_URL` z `127.0.0.1` na nazwę usługi w sieci Dockerowej (`postgres`):

```ini
POSTGRES_USER=sinuschat
POSTGRES_DB=sinuschat
POSTGRES_PASSWORD=TwojeNoweSilneHaslo
DATABASE_URL=postgres://sinuschat:TwojeNoweSilneHaslo@postgres:5432/sinuschat
```

### Krok 4: Uruchom sam kontener bazy danych w Dockerze

Upewnij się, że katalog `./db_data` jest pusty przed pierwszym startem (lub pozwól Dockerowi go zainicjalizować), a następnie uruchom usługę `postgres`:

```bash
docker compose up -d postgres
```

Poczekaj kilka sekund, aż kontener przejdzie test gotowości (`healthy`):

```bash
docker compose ps postgres
```

### Krok 5: Zaimportuj zrzut bazy do kontenera Docker

Przekaż plik `sinuschat_backup.sql` bezpośrednio do klienta `psql` wewnątrz działającego kontenera `sinuschat-postgres`:

```bash
# Wczytaj zmienne z .env, aby użyć właściwego POSTGRES_USER i POSTGRES_DB
set -a && . ./.env && set +a

docker exec -i sinuschat-postgres psql \
  -v ON_ERROR_STOP=1 \
  -U "${POSTGRES_USER:-sinuschat}" \
  -d "${POSTGRES_DB:-sinuschat}" < sinuschat_backup.sql
```

> [!NOTE]
> Ponieważ użyliśmy flag `--clean --if-exists` przy `pg_dump`, skrypt najpierw wyczyści puste tabele utworzone podczas startu kontenera przez `schema.sql`, a następnie odtworzy dokładną strukturę, dane oraz aktualne wartości sekwencji (`users_id_seq`, `bug_reports_id_seq`) ze starej bazy.

### Krok 6: Zweryfikuj dane i uruchom cały stos

Sprawdź, czy liczba użytkowników i wiadomości w kontenerze zgadza się ze stanem przed migracją:

```bash
docker exec -it sinuschat-postgres psql -U "${POSTGRES_USER:-sinuschat}" -d "${POSTGRES_DB:-sinuschat}" \
  -c "SELECT (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM groups) AS groups, (SELECT COUNT(*) FROM messages) AS messages;"
```

Uruchom kontener serwera API (przenieś do nowego `.env` ten sam `BLOCK_SECRET`, jeśli był ustawiony — bez niego serwer nie wystartuje na bazie z zaszyfrowanymi blokadami):

```bash
docker compose up -d --build
docker compose logs -f server
```

Gdy w logach zobaczysz `[SCHEMA] schemat aktualny` oraz `SinusChat server running on 0.0.0.0:3000`, migracja jest zakończona. Możesz wtedy wyłączyć stary serwer PostgreSQL na hoście (`sudo systemctl disable --now postgresql`) oraz usunąć kopię roboczą `rm -f sinuschat_backup.sql` (lub przenieść ją w bezpieczne miejsce).

---

## 7. Zadania okresowe i utrzymanie ruchu

Proces `src/jobs.js` automatycznie wykonuje w tle cykliczne zadania porządkowe (co godzinę oraz przy starcie, chyba że podano inaczej):

- **Wiadomości (`purgeOldMessages`, `purgeDeliveredMessages`, `cleanupMessagesAndGroups`):**
  - Wiadomości 1:1 potwierdzone przez odbiorcę (pong po ramce WebSocket lub `POST /api/messages/received`) są kasowane od razu; pozostałe dostarczone wiersze — co **5 minut**, gdy minie 5 minut od `delivered_at`.
  - Nieodebrane wiadomości są usuwane po upływie `MESSAGE_TTL_MS` (24 h), a nadawca dostaje powiadomienie `expiry_notice`. Wiersze nieodebrane dłużej niż **30 dni** są kasowane bezwarunkowo.
- **Kontrola przestrzeni dyskowej (`checkDiskSpace`):** Co 6 godzin serwer sprawdza wolne miejsce na dysku, na którym leży jego katalog roboczy. Poniżej **10 GB** wypisuje ostrzeżenie (`[DISK WARNING]`), a poniżej **5 GB** błąd (`[DISK CRITICAL]`).
- **Konta i grupy (`purgeScheduledAccounts`, `purgeInactiveAccounts`):**
  - Konta zaplanowane do usunięcia przez użytkownika są trwale kasowane po upływie okresu karencji (**14 dni**).
  - Nieaktywne konta są czyszczone zgodnie z ich limitem bezczynności (`auto_delete_after_sec`; domyślnie 1,5 roku dla kont anonimowych i 5 lat dla kont e-mail).
  - Uczestnicy grup nieaktywnych przez ponad **548 dni** (ok. 1,5 roku) są automatycznie wypisywani.
- **Zaproszenia i zgłoszenia (`purgeOldInvites`, `purgeOldReports`):**
  - Wykorzystane, wycofane lub wygasłe zaproszenia jednorazowe są usuwane po 24 godzinach.
  - Dane kontaktowe i diagnostyczne rozstrzygniętego zgłoszenia (`email`, `name`, `device`, `android`, `app_version`, `diagnostics`) są czyszczone **24 godziny** po decyzji administratora.
  - Zgłoszenia błędów (`bug_reports`) są trwale usuwane po **30 dniach** od ostatniej zmiany (utworzenia, odpowiedzi lub decyzji).

---

## 8. Bezpieczeństwo i zgłaszanie podatności

Znalazłeś błąd bezpieczeństwa? **Nie otwieraj publicznego zgłoszenia (Issue).**

Zgłoś podatność prywatnie zgodnie z procedurą opisaną w pliku **[SECURITY.md](SECURITY.md)**:

1. Przez funkcję **Zgłoś problem** w ustawieniach aplikacji SinusChat, lub
2. Przez prywatne zgłoszenie podatności na GitHubie (_Security → Report a vulnerability_).

Na reakcję i przygotowanie poprawki potrzebujemy do **48 godzin** od momentu potwierdzenia odbioru zgłoszenia. Badania prowadzone w dobrej wierze (bez naruszania cudzych kont i danych) są w pełni chronione.

---

## 9. Licencja

Copyright © 2026 **Sinusoide Technology**.

Kod źródłowy serwera SinusChat (`server.js` oraz katalog `src/`) jest wolnym oprogramowaniem udostępnianym na licencji **GNU Affero General Public License w wersji 3 (AGPL-3.0)** — pełny tekst znajduje się w pliku **[LICENSE](LICENSE)** — wraz z **warunkami dodatkowymi z sekcji 7 AGPL-3.0**, szczegółowo opisanymi w pliku **[NOTICE.md](NOTICE.md)**:

- **Nazwy i znaki towarowe (sekcja 7e):** Licencja nie przyznaje żadnych praw do nazw „SinusChat”, „Sinia”, „Sinusoide” ani do oficjalnego logo i ikon. Zmodyfikowane wersje muszą używać własnej nazwy.
- **Oznaczenie zmodyfikowanych wersji (sekcja 7c):** Zmieniona wersja musi być wyraźnie oznaczona jako zmodyfikowana i niepochodząca od Sinusoide Technology. Nie wolno przedstawiać jej jako oficjalnego serwera SinusChat.
- **Zachowanie informacji o autorstwie (sekcja 7b):** Należy zachować wszystkie informacje o prawach autorskich, autorach oraz plik `NOTICE.md`.
- **Brak sugestii poparcia (sekcja 7d):** Nie wolno używać nazwy Sinusoide Technology do promowania zmodyfikowanych wersji ani sugerować ich oficjalnego poparcia.
- **Udostępnianie przez sieć (sekcja 13 AGPL-3.0):** Każdy, kto uruchamia zmodyfikowaną wersję serwera i umożliwia użytkownikom interakcję z nią przez sieć, ma obowiązek udostępnić im pełny kod źródłowy swojej wersji.

Zewnętrzne biblioteki wykorzystywane przez projekt (`fastify`, `pg`, `jsonwebtoken` i inne) podlegają własnym licencjom (głównie MIT). Pełna dokumentacja prawna znajduje się na stronie [sinusoide.pl/dokumentacja.html](https://sinusoide.pl/dokumentacja.html).

---

## 10. English Summary

**SinusChat Server** is the backend API and WebSocket relay for the [SinusChat](https://sinusoide.pl) end-to-end encrypted messenger, built with **Fastify (Node.js)** and **PostgreSQL**.

- **Zero-Knowledge Relay:** Handles Signal Protocol key distribution (including post-quantum Kyber prekeys), Sealed Sender messages, 1-on-1 and group WebRTC call signalling, and wake-up pushes (ntfy & FCM). Message contents are encrypted on client devices.
- **Deployment Options:**
  1. **Docker Compose (Recommended):** Run `cp .env.example .env`, set `POSTGRES_PASSWORD` and secrets, and start the hardened stack (`node:24-alpine` + `postgres:18-alpine`) with `docker compose up -d --build`.
  2. **Systemd on Host:** Use the hardened unit in [`deploy/sinuschat.service`](deploy/sinuschat.service).
  3. **Direct Node.js execution:** Load `.env` (`set -a && . ./.env && set +a`) and run `npm start` (`node server.js`).
- **Reverse Proxy Required:** The server binds to `127.0.0.1` and trusts the `X-Real-IP` header. Always place `nginx` in front of it with `proxy_set_header X-Real-IP $remote_addr;`.
- **License:** Licensed under **AGPL-3.0-only** with additional section 7 terms regarding trademarks, modified versions, attribution, and non-endorsement. See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md) for details, and [SECURITY.md](SECURITY.md) for vulnerability reporting.
