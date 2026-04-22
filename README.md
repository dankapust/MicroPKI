# MicroPKI

Минимальная реализация инфраструктуры открытых ключей (PKI) для обучения и демонстрации. Поддерживает корневой УЦ, промежуточный УЦ, сертификаты конечных сущностей, отзыв (CRL), сервер репозитория и OCSP-ответчик.

## Зависимости

- **Python** 3.8 и выше
- **cryptography** ≥ 3.0
- **fastapi** и **uvicorn** (для серверов репозитория и OCSP)

Полный список зависимостей — в `requirements.txt`.

## Сборка / Установка

```bash
# Создать виртуальное окружение (рекомендуется)
python -m venv venv
# Windows:
venv\Scripts\activate
# Unix/macOS:
# source venv/bin/activate

# Установить зависимости
pip install -r requirements.txt

# Установить пакет в режиме разработки
pip install -e .
```

## Запуск тестов

```bash
pytest tests/ -v
```

Если вы установили только зависимости без `pip install -e .`, запускайте CLI так:

```bash
python -m micropki ca init ...
```

## Быстрый старт (Windows PowerShell)

Все команды выполняются из корневой папки проекта.

**1. Установка зависимостей (если ещё не сделано):**

```powershell
pip install -r requirements.txt
pip install -e .
```

**2. Создание файлов с паролями:**

```powershell
mkdir secrets -Force
Set-Content -Path secrets\ca.pass -Value "your-secret-passphrase" -NoNewline
Set-Content -Path secrets\inter.pass -Value "intermediate-passphrase" -NoNewline
```

**3. Инициализация корневого УЦ:**

```powershell
micropki ca init --subject "/CN=Demo Root CA" --key-type rsa --key-size 4096 --passphrase-file secrets\ca.pass --out-dir .\pki
```

**4. Проверка сертификата корневого УЦ:**

```powershell
micropki ca verify --cert pki\certs\ca.cert.pem
```

**5. Создание промежуточного УЦ:**

```powershell
micropki ca issue-intermediate --root-cert pki\certs\ca.cert.pem --root-key pki\private\ca.key.pem --root-pass-file secrets\ca.pass --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" --key-type rsa --key-size 4096 --passphrase-file secrets\inter.pass --out-dir .\pki --validity-days 1825 --pathlen 0
```

**6. Выпуск серверного сертификата:**

```powershell
micropki ca issue-cert --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\inter.pass --template server --subject "/CN=example.com" --san dns:example.com --out-dir pki\certs
```

**7. Проверка цепочки доверия:**

```powershell
micropki ca verify-chain --leaf pki\certs\example.com.cert.pem --intermediate pki\certs\intermediate.cert.pem --root pki\certs\ca.cert.pem
```

## Использование (Спринт 1) — Корневой УЦ

### Создание файла с паролем

**Windows (PowerShell):**

```powershell
mkdir secrets -Force
Set-Content -Path secrets\ca.pass -Value "your-secret-passphrase" -NoNewline
```

**Linux/macOS:**

```bash
mkdir -p secrets
printf '%s' 'your-secret-passphrase' > secrets/ca.pass
```

### Инициализация корневого УЦ (RSA 4096)

```powershell
micropki ca init --subject "/CN=Demo Root CA" --key-type rsa --key-size 4096 --passphrase-file secrets\ca.pass --out-dir .\pki
```

### Инициализация корневого УЦ (ECC P-384)

```bash
micropki ca init --subject "CN=ECC Root CA,O=MicroPKI" --key-type ecc --key-size 384 --passphrase-file secrets/ca.pass --out-dir ./pki
```

### Проверка сертификата корневого УЦ

```powershell
micropki ca verify --cert pki\certs\ca.cert.pem
```

Проверка через OpenSSL:

```bash
openssl x509 -in pki/certs/ca.cert.pem -text -noout
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem
```

## Использование (Спринт 2) — Промежуточный УЦ и сертификаты конечных сущностей

### Создание промежуточного УЦ, подписанного корневым

```powershell
Set-Content -Path secrets\inter.pass -Value "intermediate-passphrase" -NoNewline
micropki ca issue-intermediate --root-cert pki\certs\ca.cert.pem --root-key pki\private\ca.key.pem --root-pass-file secrets\ca.pass --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" --key-type rsa --key-size 4096 --passphrase-file secrets\inter.pass --out-dir .\pki --validity-days 1825 --pathlen 0
```

### Выпуск серверного сертификата

```powershell
micropki ca issue-cert --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\inter.pass --template server --subject "CN=example.com,O=MicroPKI" --san dns:example.com --san dns:www.example.com --san ip:192.168.1.10 --out-dir pki\certs --validity-days 365
```

### Выпуск клиентского сертификата

```powershell
micropki ca issue-cert --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\inter.pass --template client --subject "CN=Alice Smith" --san email:alice@example.com --out-dir pki\certs
```

### Выпуск сертификата для подписи кода

```powershell
micropki ca issue-cert --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\inter.pass --template code_signing --subject "CN=MicroPKI Code Signer" --out-dir pki\certs
```

### Проверка цепочки сертификатов (лист → промежуточный → корневой)

```powershell
micropki ca verify-chain --leaf pki\certs\example.com.cert.pem --intermediate pki\certs\intermediate.cert.pem --root pki\certs\ca.cert.pem
```

Совместимость с OpenSSL:

```bash
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/intermediate.cert.pem
openssl verify -CAfile pki/certs/ca.cert.pem -untrusted pki/certs/intermediate.cert.pem pki/certs/example.com.cert.pem
```

## Использование (Спринт 3) — Сервер репозитория

### Инициализация базы данных сертификатов

```bash
micropki db init --db-path ./pki/micropki.db
```

### Запуск HTTP-сервера репозитория

```bash
micropki repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs
```

### Примеры API-запросов (curl)

```bash
# Получить сертификат по серийному номеру
curl http://localhost:8080/certificate/2A7F... --output cert.pem

# Получить сертификат корневого УЦ
curl http://localhost:8080/ca/root --output root.pem

# Получить сертификат промежуточного УЦ
curl http://localhost:8080/ca/intermediate --output intermediate.pem

# Точка распространения CRL
curl http://localhost:8080/crl?ca=intermediate --output intermediate.crl.pem
openssl crl -inform PEM -in intermediate.crl.pem -text -noout
```

## Использование (Спринт 4) — Отзыв сертификатов и CRL

### Отзыв сертификата

```bash
micropki ca revoke <серийный_номер_hex> --reason keyCompromise --db-path ./pki/micropki.db
```

Поддерживаемые причины отзыва: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aACompromise`.

### Генерация списка отозванных сертификатов (CRL)

```bash
micropki ca gen-crl --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/inter.pass --out-dir ./pki --db-path ./pki/micropki.db --next-update 7
```

## Использование (Спринт 5) — OCSP-ответчик

### Выпуск сертификата для OCSP-ответчика

OCSP-ответчику нужен собственный сертификат с расширенным использованием ключа `id-kp-OCSPSigning`. Закрытый ключ сохраняется **без шифрования**, чтобы ответчик мог загрузить его без пароля:

```powershell
micropki ca issue-ocsp-cert --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\inter.pass --subject "/CN=OCSP Responder" --san dns:localhost --out-dir pki\certs --validity-days 365
```

Результат:
- `pki/certs/OCSP_Responder.cert.pem` — сертификат подписи OCSP
- `pki/certs/OCSP_Responder.key.pem` — незашифрованный закрытый ключ

### Запуск OCSP-ответчика

```powershell
micropki ocsp serve --host 127.0.0.1 --port 8081 --db-path ./pki/micropki.db --responder-cert ./pki/certs/OCSP_Responder.cert.pem --responder-key ./pki/certs/OCSP_Responder.key.pem --ca-cert ./pki/certs/intermediate.cert.pem
```

Сервер начинает слушать на `http://127.0.0.1:8081` и принимает GET и POST OCSP-запросы (RFC 6960).

### Проверка статуса сертификата через OpenSSL

Запрос статуса действующего сертификата:

```powershell
openssl ocsp -issuer pki\certs\intermediate.cert.pem -cert pki\certs\example.com.cert.pem -url http://127.0.0.1:8081 -VAfile pki\certs\OCSP_Responder.cert.pem
```

Ожидаемый вывод для действительного сертификата:

```
Response verify OK
pki\certs\example.com.cert.pem: good
    This Update: Apr  8 07:40:25 2026 GMT
```

### Отзыв и повторная проверка

```powershell
micropki ca revoke <серийный_номер_hex> --reason keyCompromise --force
openssl ocsp -issuer pki\certs\intermediate.cert.pem -cert pki\certs\example.com.cert.pem -url http://127.0.0.1:8081 -VAfile pki\certs\OCSP_Responder.cert.pem
```

Ожидаемый вывод после отзыва:

```
Response verify OK
pki\certs\example.com.cert.pem: revoked
    This Update: Apr  8 07:47:17 2026 GMT
    Reason: keyCompromise
    Revocation Time: Apr  8 07:47:10 2026 GMT
```

## Использование (Спринт 6) — Клиентские инструменты и валидация

### Генерация ключа и CSR

Генерация закрытого ключа (RSA-2048) и запроса на подпись сертификата (PKCS#10):

```powershell
micropki client gen-csr --subject "/CN=app.example.com" --key-type rsa --key-size 2048 --san dns:app.example.com --san dns:api.example.com --out-key ./app.key.pem --out-csr ./app.csr.pem
```

### Запрос сертификата через API

Запустите сервер репозитория с поддержкой подписания:

```powershell
micropki repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\inter.pass
```

Отправьте CSR:

```powershell
micropki client request-cert --csr ./app.csr.pem --template server --ca-url http://127.0.0.1:8080 --out-cert ./app.cert.pem
```

### Валидация цепочки сертификатов

```powershell
micropki client validate --cert ./app.cert.pem --untrusted pki\certs\intermediate.cert.pem --trusted pki\certs\ca.cert.pem --mode chain
```

Полная валидация с проверкой отзыва (OCSP + CRL):

```powershell
micropki client validate --cert ./app.cert.pem --untrusted pki\certs\intermediate.cert.pem --trusted pki\certs\ca.cert.pem --ocsp --ocsp-url http://127.0.0.1:8081 --mode full
```

### Проверка статуса отзыва (OCSP -> CRL fallback)

```powershell
micropki client check-status --cert ./app.cert.pem --ca-cert pki\certs\intermediate.cert.pem --ocsp-url http://127.0.0.1:8081
```

Логика: OCSP первым, при неудаче — CRL, оба недоступны — статус `unknown`.

## Структура проекта

```
micropki/
  __init__.py
  __main__.py          # python -m micropki
  cli.py               # парсер аргументов (ca, db, repo, ocsp, client)
  ca.py                # корневой/промежуточный УЦ, выпуск сертификатов
  certificates.py      # построение X.509, расширения, разбор DN
  chain.py             # базовая валидация цепочки
  client.py            # клиент: gen-csr, request-cert, validate, check-status
  crl.py               # генерация CRL
  crypto_utils.py      # PEM, ключи, шифрование, загрузка паролей
  csr.py               # генерация CSR, подписание
  database.py          # SQLite: certificates, crl_metadata
  logger.py            # логирование (файл/stderr, ISO 8601)
  ocsp.py              # OCSP-ответы (RFC 6960)
  ocsp_responder.py    # HTTP-сервер OCSP (FastAPI)
  repo.py              # HTTP-репозиторий + POST /request-cert
  repository.py        # CRUD сертификатов в БД
  revocation.py        # внутренний отзыв сертификатов
  revocation_check.py  # клиентская проверка: OCSP, CRL, fallback, AIA/CDP
  serial.py            # серийные номера
  templates.py         # шаблоны (server, client, code_signing, ocsp)
  validation.py        # валидация цепочки по RFC 5280
  audit.py             # аудит-логирование (NDJSON + SHA-256 hash chain)
  policy.py            # политики безопасности (ключи, сроки, SAN, алгоритмы)
  ratelimit.py         # ограничение запросов (token bucket per IP)
  transparency.py      # симуляция Certificate Transparency (CT) лога
  compromise.py        # компрометация ключей (блокировка, экстренный CRL)
tests/                 # pytest
scripts/               # verify_key_cert_match.py
requirements.txt
pyproject.toml
```

## Использование (Спринт 7) — Безопасность и аудит

### Система аудита

Все критические операции записываются в NDJSON-файл `./pki/audit/audit.log` с криптографической цепочкой хешей SHA-256. Каждая запись содержит:

- `timestamp` — время в ISO 8601 с микросекундами
- `level` — уровень (AUDIT, INFO, ERROR)
- `operation` — тип операции (ca_init, issue_certificate, revoke_certificate и т.д.)
- `status` — результат (started, success, failure)
- `message` — описание
- `metadata` — детали (serial, subject, template, reason)
- `integrity` — хеш-цепочка (`prev_hash`, `hash`)

**Запрос аудит-лога:**

```powershell
# Все записи
micropki audit query

# Фильтрация по операции и формат JSON
micropki audit query --operation issue_certificate --format json

# Фильтрация по уровню
micropki audit query --level AUDIT --format table

# С проверкой целостности
micropki audit query --verify
```

**Проверка целостности аудит-лога:**

```powershell
micropki audit verify
# Вывод: "Audit log integrity: OK" или "INTEGRITY FAILURE: ..."
```

### Политики безопасности

Все политики проверяются автоматически при выпуске сертификатов:

| Политика | Правило |
|----------|---------|
| Размер RSA-ключа (Root) | ≥ 4096 бит |
| Размер RSA-ключа (Intermediate) | ≥ 3072 бит |
| Размер RSA-ключа (End-entity) | ≥ 2048 бит |
| ECC-ключ (Root/Intermediate) | P-384 |
| ECC-ключ (End-entity) | P-256 или P-384 |
| Срок действия Root CA | ≤ 3650 дней |
| Срок действия Intermediate CA | ≤ 1825 дней |
| Срок действия конечного сертификата | ≤ 365 дней |
| Wildcard SAN (*.example.com) | Запрещён по умолчанию |
| SAN-типы для server | Только dns, ip |
| SAN-типы для client | dns, email |
| SAN-типы для code_signing | dns, uri |
| Path length (Intermediate) | Должен быть 0 |
| Алгоритм подписи | SHA-256+ (SHA-1 запрещён) |

При нарушении политики выпуск блокируется, создаётся запись AUDIT.

### Ограничение запросов (Rate Limiting)

Серверы репозитория и OCSP поддерживают rate limiting по IP:

```powershell
# Репозиторий с ограничением 5 запросов/сек, burst 10
micropki repo serve --host 127.0.0.1 --port 8080 --rate-limit 5 --rate-burst 10

# OCSP-ответчик с ограничением
micropki ocsp serve --responder-cert ... --responder-key ... --ca-cert ... --rate-limit 10 --rate-burst 20
```

При превышении лимита сервер возвращает HTTP 429 с заголовком `Retry-After`.

### Симуляция Certificate Transparency (CT)

Каждый выпущенный сертификат записывается в `./pki/audit/ct.log`. Формат строки:
```
timestamp | serial_hex | subject_dn | sha256_fingerprint | issuer_dn
```

Проверка включения сертификата в CT-лог — поиск серийного номера:
```powershell
Select-String -Path .\pki\audit\ct.log -Pattern "SERIAL_HEX"
```

### Симуляция компрометации ключа

```powershell
# Пометить ключ сертификата как скомпрометированный
micropki ca compromise --cert pki\certs\example.com.cert.pem --force --db-path pki\micropki.db

# С генерацией экстренного CRL
micropki ca compromise --cert pki\certs\example.com.cert.pem --force --db-path pki\micropki.db --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\inter.pass --out-dir pki
```

После компрометации:
- Сертификат отзывается с причиной `keyCompromise`
- Хеш публичного ключа записывается в таблицу `compromised_keys`
- Любой будущий CSR с тем же ключом будет отклонён
- Создаётся запись AUDIT высокой важности
- Опционально генерируется экстренный CRL

### Расширение БД

Таблица `compromised_keys` создаётся автоматически при `db init`:

```sql
CREATE TABLE IF NOT EXISTS compromised_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key_hash TEXT UNIQUE NOT NULL,
    certificate_serial TEXT NOT NULL,
    compromise_date TEXT NOT NULL,
    compromise_reason TEXT NOT NULL
);
```

## Лицензия

Для образовательных целей и демонстрации.

