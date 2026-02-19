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

## Project layout

```
micropki/
  __init__.py
  cli.py           # argument parser, ca init / ca verify
  ca.py            # root CA logic
  certificates.py  # X.509 build and extensions
  crypto_utils.py  # PEM, key load, encryption
  logger.py        # logging setup
tests/             # pytest
requirements.txt
pyproject.toml     # for pip install -e .
```

## License

Educational / demonstration use.
