# MicroPKI

A minimal, single-handed PKI implementation for learning and demonstration. Establishes a self-signed Root CA with secure key storage and basic audit logging.

## Dependencies

- **Python** 3.8 or higher
- **cryptography** ≥ 3.0 (see `requirements.txt`)

## Build / Setup

```bash
# Clone the repository (if from remote)
# git clone <repo-url>
# cd Kripta

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

## Usage (Sprint 3)

### Initialize certificate database

```powershell
micropki db init --db-path .\pki\micropki.db
```

### List certificates from database

```powershell
micropki ca list-certs --db-path .\pki\micropki.db --status valid --format table
micropki ca list-certs --db-path .\pki\micropki.db --format json
```

### Show certificate PEM by serial

```powershell
micropki ca show-cert 2A7F... --db-path .\pki\micropki.db
```

### Start repository HTTP server

```powershell
micropki repo serve --host 127.0.0.1 --port 8080 --db-path .\pki\micropki.db --cert-dir .\pki\certs
```

### API examples (curl)

```bash
curl http://127.0.0.1:8080/certificate/2A7F...
curl http://127.0.0.1:8080/ca/root
curl http://127.0.0.1:8080/ca/intermediate
curl http://127.0.0.1:8080/crl
```

**Windows PowerShell note:** built-in `curl` is an alias to `Invoke-WebRequest` and may show script parsing warnings or throw on non-2xx responses.
Use one of these:

```powershell
# Preferred: real curl binary (use a real hex serial from list-certs — do NOT paste <...> brackets in PowerShell)
curl.exe http://127.0.0.1:8080/certificate/69D0F0D43DA40F3D
curl.exe http://127.0.0.1:8080/ca/root
curl.exe http://127.0.0.1:8080/ca/intermediate
curl.exe -i http://127.0.0.1:8080/crl

# Or PowerShell cmdlet without IE parser
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/certificate/69D0F0D43DA40F3D
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/ca/root
```

**PowerShell и символы `<` `>`:** в примерах ниже *не* используйте запись вида `<SERIAL_HEX>` — в PowerShell `<` зарезервирован и даёт ошибку «Оператор "<" зарезервирован…». Подставьте реальный serial из `micropki ca list-certs` или заведите переменную: `$s = "69BEE1AC4AC1B70D"; micropki ca revoke $s --force ...`.

## Usage (Sprint 4) — revocation and CRL

PKI layout includes a `crl/` directory under `--out-dir` (e.g. `pki/crl/root.crl.pem`, `pki/crl/intermediate.crl.pem`). The database gains a `crl_metadata` table (migration runs on `db init` or first use).

### Revoke a certificate (by serial, hex)

```powershell
# Example serial — замените на свой из list-certs (без угловых скобок)
micropki ca revoke 69BEE1AC4AC1B70D --reason keyCompromise --db-path .\pki\micropki.db --out-dir .\pki --force
# или: $s = "69BEE1AC4AC1B70D"; micropki ca revoke $s --reason keyCompromise --force --db-path .\pki\micropki.db --out-dir .\pki
```

Supported `--reason` values (case-insensitive): `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aACompromise`.

Optional: regenerate the issuing CA’s CRL immediately after revoke (default CRL path under `pki\crl\`):

```powershell
micropki ca revoke 69BEE1AC4AC1B70D --reason superseded --force --crl --ca-pass-file secrets\inter.pass --db-path .\pki\micropki.db --out-dir .\pki
micropki ca revoke 69BEE1AC4AC1B70D --reason superseded --force --crl .\backup\my.crl.pem --ca-pass-file secrets\inter.pass --db-path .\pki\micropki.db --out-dir .\pki
```

`--crl` without a path selects `...\crl\root.crl.pem` or `...\crl\intermediate.crl.pem` based on the certificate’s issuer. `--ca-pass-file` is required whenever `--crl` is used.

### Generate or refresh a full CRL

```powershell
micropki ca gen-crl --ca intermediate --next-update 14 --out-dir .\pki --db-path .\pki\micropki.db --ca-pass-file secrets\inter.pass
micropki ca gen-crl --ca root --out-file .\backup\root.crl.pem --out-dir .\pki --db-path .\pki\micropki.db --ca-pass-file secrets\ca.pass
```

If `--ca` is a PEM file path, pass the matching key with `--ca-key`.

### Check revocation status (database, optional CRL file)

```powershell
micropki ca check-revoked 69BEE1AC4AC1B70D --db-path .\pki\micropki.db
micropki ca check-revoked 69BEE1AC4AC1B70D --db-path .\pki\micropki.db --crl .\pki\crl\intermediate.crl.pem
```

### HTTP repository — fetch CRL

Default `GET /crl` returns the **intermediate** CA CRL. Use `?ca=root` for the root CRL. Alternative paths: `/crl/intermediate.crl`, `/crl/root.crl`.

```powershell
micropki repo serve --host 127.0.0.1 --port 8080 --db-path .\pki\micropki.db --cert-dir .\pki\certs --pki-dir .\pki
```

```powershell
curl.exe -i -H "Accept: application/pkix-crl" http://127.0.0.1:8080/crl
curl.exe -i http://127.0.0.1:8080/crl?ca=root
curl.exe -i http://127.0.0.1:8080/crl/intermediate.crl
```

If the CRL file is missing, the server returns **404**. Responses include `Content-Type: application/pkix-crl`, `Last-Modified`, `Cache-Control: max-age=...` (derived from CRL `nextUpdate` when parseable), and `ETag`.

### Verify CRL with OpenSSL

```bash
openssl crl -inform PEM -in pki/crl/intermediate.crl.pem -text -noout
openssl crl -in pki/crl/intermediate.crl.pem -inform PEM -CAfile pki/certs/intermediate.cert.pem -noout
```

The second command should report **`verify OK`** in stderr when the CRL is signed by that CA.

**If `openssl` is not installed** (typical on Windows), inspect the CRL with Python (uses the same `cryptography` library as MicroPKI):

```powershell
python -c "from cryptography import x509; from pathlib import Path; c=x509.load_pem_x509_crl(Path('pki/crl/intermediate.crl.pem').read_bytes()); n=c.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number; print('CRL Number:', n); print('Revoked:', [hex(r.serial_number) for r in c])"
```

### Verify a revoked certificate (conceptual)

MicroPKI does not terminate TLS for you. To experiment with OpenSSL revocation checking you need a TLS server that serves the revoked leaf, plus a trust/chain setup and `openssl s_client -crl_check` (see Sprint 4 technical doc). Locally you can confirm revocation via `ca check-revoked`, the database, and the CRL PEM contents (`openssl crl -text` or the Python one-liner above).

## Project layout

```
micropki/
  __init__.py
  __main__.py       # python -m micropki
  cli.py            # argument parser: ca, db, repo (incl. revoke, gen-crl, check-revoked)
  ca.py             # Root CA init, Intermediate CA, end-entity issuance, verify, CA path resolution
  certificates.py   # X.509 build and extensions, DN parsing
  csr.py            # CSR generation, Intermediate/end-entity signing
  crl.py            # CRL build/sign (RFC 5280), CRL number + metadata persistence
  revocation.py     # Revocation reasons, DB revoke workflow
  templates.py      # Certificate templates (server, client, code_signing), SAN parsing
  chain.py          # Chain validation: signatures, validity, constraints
  crypto_utils.py   # PEM, key generation, encryption, passphrase loading
  database.py       # SQLite schema, certificates + crl_metadata
  repository.py     # HTTP repository (certificates, CA PEMs, CRL)
  logger.py         # logging setup (file/stderr, ISO 8601)
tests/              # pytest (includes Sprint 4 CRL/revocation tests)
scripts/            # verify_key_cert_match.py
requirements.txt
pyproject.toml
```

## License

Educational / demonstration use.
