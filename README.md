# MicroPKI

A minimal, single-handed PKI implementation for learning and demonstration. Establishes a self-signed Root CA with secure key storage and basic audit logging.

## Dependencies

- **Python** 3.8 or higher
- **cryptography** ≥ 3.0 (see `requirements.txt`)

## Build / Setup

```bash
# Clone the repository (if from remote)
# git clone <repo-url>
# cd MicroPKI

# Create virtual environment (recommended)
python -m venv venv
# Windows:
venv\Scripts\activate
# Unix/macOS:
# source venv/bin/activate
# If PowerShell blocks Activate.ps1 (execution policy), use:
#   venv\Scripts\activate.bat   (from cmd), or
#   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Install dependencies
pip install -r requirements.txt

# Install the package in editable mode so `micropki` is available
pip install -e .
```

## Running tests

```bash
pytest tests/ -v
# or
make test
```

If you use only `pip install -r requirements.txt` without `pip install -e .`, run the CLI as:

```bash
python -m micropki ca init ...
```

## Quick verification (Windows, полная проверка работы)

Выполняйте команды по порядку из каталога проекта `C:\Users\KapDon\.cursor\Kripta`:

```powershell
cd C:\Users\KapDon\.cursor\Kripta
```

**1. Установка зависимостей и пакета (если ещё не сделано):**

```powershell
pip install -r requirements.txt
pip install -e .
```

**2. Создать каталог и файл с паролем:**

```powershell
mkdir secrets -Force
Set-Content -Path C:\Users\KapDon\.cursor\Kripta\secrets\ca.pass -Value "your-secret-passphrase" -NoNewline
```

**3. Инициализировать Root CA:**

```powershell
micropki ca init --subject "/CN=Demo Root CA" --key-type rsa --key-size 4096 --passphrase-file C:\Users\KapDon\.cursor\Kripta\secrets\ca.pass --out-dir C:\Users\KapDon\.cursor\Kripta\pki
```

**4. Проверить сертификат:**

```powershell
micropki ca verify --cert C:\Users\KapDon\.cursor\Kripta\pki\certs\ca.cert.pem
```

Ожидаемый вывод: `Certificate verification succeeded: ...` и код выхода 0.

**5. (Опционально) Проверить, что ключ соответствует сертификату:**

```powershell
python C:\Users\KapDon\.cursor\Kripta\scripts\verify_key_cert_match.py C:\Users\KapDon\.cursor\Kripta\pki\private\ca.key.pem C:\Users\KapDon\.cursor\Kripta\pki\certs\ca.cert.pem C:\Users\KapDon\.cursor\Kripta\secrets\ca.pass
```

Ожидаемый вывод: `OK: Private key matches certificate public key (sign/verify succeeded).`

**6. Запустить тесты:**

```powershell
cd C:\Users\KapDon\.cursor\Kripta
pytest tests/ -v
```

---

Если вы уже в каталоге `C:\Users\KapDon\.cursor\Kripta`, можно использовать относительные пути:

```powershell
Set-Content -Path secrets\ca.pass -Value "your-secret-passphrase" -NoNewline
micropki ca init --subject "/CN=Demo Root CA" --key-type rsa --key-size 4096 --passphrase-file secrets\ca.pass --out-dir .\pki
micropki ca verify --cert pki\certs\ca.cert.pem
python scripts\verify_key_cert_match.py pki\private\ca.key.pem pki\certs\ca.cert.pem secrets\ca.pass
pytest tests/ -v
```

## Usage (Sprint 1)

### Create passphrase file first

**Windows (PowerShell):** Use `utf8` (not `utf8NoBOM` on older PowerShell):

```powershell
mkdir secrets -Force
Set-Content -Path secrets\ca.pass -Value "your-secret-passphrase" -NoNewline
# or (adds newline; micropki strips it):
"your-secret-passphrase" | Out-File -Encoding utf8 secrets\ca.pass
```

**Linux/macOS:**

```bash
mkdir -p secrets
printf '%s' 'your-secret-passphrase' > secrets/ca.pass
```

### Initialize Root CA (RSA 4096)

```bash
# CMD (Windows)
micropki ca init ^
    --subject "/CN=Demo Root CA" ^
    --key-type rsa ^
    --key-size 4096 ^
    --passphrase-file secrets\ca.pass ^
    --out-dir .\pki

# PowerShell
micropki ca init --subject "/CN=Demo Root CA" --key-type rsa --key-size 4096 --passphrase-file secrets\ca.pass --out-dir .\pki
```

### Initialize Root CA (ECC P-384)

```bash
micropki ca init ^
    --subject "CN=ECC Root CA,O=MicroPKI" ^
    --key-type ecc ^
    --key-size 384 ^
    --passphrase-file secrets/ca.pass ^
    --out-dir ./pki
```

### Verify Root CA certificate

```bash
micropki ca verify --cert pki/certs/ca.cert.pem
# Windows:
micropki ca verify --cert pki\certs\ca.cert.pem
```

Or with OpenSSL:

```bash
openssl x509 -in pki/certs/ca.cert.pem -text -noout
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem
```

## Usage (Sprint 3)

### Initialize the certificate database

```bash
micropki db init --db-path ./pki/micropki.db
```

### Start the repository HTTP server

```bash
micropki repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs
```

### Example API requests (curl)

# Retrieve a certificate by serial
$ curl http://localhost:8080/certificate/2A7F... --output cert.pem

# Retrieve the Root CA certificate
$ curl http://localhost:8080/ca/root --output root.pem

# Retrieve the Intermediate CA certificate
$ curl http://localhost:8080/ca/intermediate --output intermediate.pem

# CRL endpoint
$ curl http://localhost:8080/crl?ca=intermediate --output intermediate.crl.pem
$ openssl crl -inform PEM -in intermediate.crl.pem -text -noout

## Usage (Sprint 2)

### Create Intermediate CA signed by Root CA

```powershell
Set-Content -Path secrets\inter.pass -Value "intermediate-passphrase" -NoNewline
micropki ca issue-intermediate --root-cert pki\certs\ca.cert.pem --root-key pki\private\ca.key.pem --root-pass-file secrets\ca.pass --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" --key-type rsa --key-size 4096 --passphrase-file secrets\inter.pass --out-dir .\pki --validity-days 1825 --pathlen 0
```

### Issue a server certificate

```powershell
micropki ca issue-cert --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\inter.pass --template server --subject "CN=example.com,O=MicroPKI" --san dns:example.com --san dns:www.example.com --san ip:192.168.1.10 --out-dir pki\certs --validity-days 365
```

### Issue a client certificate

```powershell
micropki ca issue-cert --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\inter.pass --template client --subject "CN=Alice Smith" --san email:alice@example.com --out-dir pki\certs
```

### Issue a code signing certificate

```powershell
micropki ca issue-cert --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\inter.pass --template code_signing --subject "CN=MicroPKI Code Signer" --out-dir pki\certs
```

### Validate certificate chain (leaf → intermediate → root)

```powershell
micropki ca verify-chain --leaf pki\certs\example.com.cert.pem --intermediate pki\certs\intermediate.cert.pem --root pki\certs\ca.cert.pem
```

OpenSSL interoperability:

```bash
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/intermediate.cert.pem
openssl verify -CAfile pki/certs/ca.cert.pem -untrusted pki/certs/intermediate.cert.pem pki/certs/example.com.cert.pem
```

## Usage (Sprint 4)

### Revoke a certificate

```bash
micropki ca revoke <serial_hex> --reason keyCompromise --db-path ./pki/micropki.db
```
Supported reasons include: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aACompromise`.

### Generate CRL

```bash
micropki ca gen-crl --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file secrets/inter.pass --out-dir ./pki --db-path ./pki/micropki.db --next-update 7
```

## Project layout

```
micropki/
  __init__.py
  __main__.py       # python -m micropki
  cli.py            # argument parser: ca init, issue-intermediate, issue-cert, verify, verify-chain, revoke, gen-crl
  ca.py             # Root CA init, Intermediate CA, end-entity issuance, verify
  certificates.py   # X.509 build and extensions, DN parsing
  crl.py            # CRL generation tools
  csr.py            # CSR generation, Intermediate/end-entity signing
  database.py       # SQLite certificate and CRL metadata storage
  repo.py           # HTTP Server for certificates and CRL distribution
  repository.py     # Database CRUD operations
  revocation.py     # Certificate revocation handling
  templates.py      # Certificate templates (server, client, code_signing), SAN parsing
  chain.py          # Chain validation: signatures, validity, constraints
  crypto_utils.py   # PEM, key generation, encryption, passphrase loading
  logger.py         # logging setup (file/stderr, ISO 8601)
tests/              # pytest
scripts/            # verify_key_cert_match.py
requirements.txt
pyproject.toml
```

## License

Educational / demonstration use.
