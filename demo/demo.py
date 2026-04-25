import os
import sys
import time
import shutil
import subprocess
from pathlib import Path

def run_cmd(cmd, env=None, check=True):
    print(f"\n[DEMO] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, env=env, text=True, capture_output=True)
    if result.returncode != 0:
        print(f"[FAIL] Command failed with code {result.returncode}")
        print(f"STDOUT:\n{result.stdout}")
        print(f"STDERR:\n{result.stderr}")
        if check:
            sys.exit(result.returncode)
    else:
        print("[PASS] Command succeeded.")
    return result

def main():
    print("========================================")
    print("      MicroPKI Demonstration Script     ")
    print("========================================")
    
    base_dir = Path.cwd()
    demo_pki = base_dir / "demo_pki"
    demo_secrets = base_dir / "demo_secrets"
    
    # 1. Setup Environment
    print("\n--- 1. Setting up Environment ---")
    if demo_pki.exists():
        shutil.rmtree(demo_pki)
    if demo_secrets.exists():
        shutil.rmtree(demo_secrets)
        
    demo_pki.mkdir()
    demo_secrets.mkdir()
    
    ca_pass = demo_secrets / "ca.pass"
    inter_pass = demo_secrets / "inter.pass"
    ca_pass.write_text("demo-root-pass")
    inter_pass.write_text("demo-inter-pass")
    
    micropki_cmd = [sys.executable, "-m", "micropki"]
    
    # 2. Initialise the Root CA
    print("\n--- 2. Initialising Root CA ---")
    run_cmd(micropki_cmd + [
        "ca", "init", 
        "--subject", "/CN=Demo Root CA",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(ca_pass),
        "--out-dir", str(demo_pki),
        "--validity-days", "3650"
    ])
    
    # 3. Initialise the Intermediate CA
    print("\n--- 3. Initialising Intermediate CA ---")
    run_cmd(micropki_cmd + [
        "ca", "issue-intermediate",
        "--root-cert", str(demo_pki / "certs" / "ca.cert.pem"),
        "--root-key", str(demo_pki / "private" / "ca.key.pem"),
        "--root-pass-file", str(ca_pass),
        "--subject", "/CN=Demo Intermediate CA",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(inter_pass),
        "--out-dir", str(demo_pki),
        "--validity-days", "1825",
        "--pathlen", "0"
    ])
    
    # 4. Issue Server, Client, and OCSP Certificates
    print("\n--- 4. Issuing Certificates ---")
    # Server
    run_cmd(micropki_cmd + [
        "ca", "issue-cert",
        "--ca-cert", str(demo_pki / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(demo_pki / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(inter_pass),
        "--template", "server",
        "--subject", "/CN=demo.example.com",
        "--san", "dns:demo.example.com",
        "--out-dir", str(demo_pki / "certs"),
        "--db-path", str(demo_pki / "micropki.db")
    ])
    # Client
    run_cmd(micropki_cmd + [
        "ca", "issue-cert",
        "--ca-cert", str(demo_pki / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(demo_pki / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(inter_pass),
        "--template", "client",
        "--subject", "/CN=Demo Client",
        "--san", "email:client@example.com",
        "--out-dir", str(demo_pki / "certs"),
        "--db-path", str(demo_pki / "micropki.db")
    ])
    # OCSP
    run_cmd(micropki_cmd + [
        "ca", "issue-ocsp-cert",
        "--ca-cert", str(demo_pki / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(demo_pki / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(inter_pass),
        "--subject", "/CN=Demo OCSP Responder",
        "--out-dir", str(demo_pki / "certs"),
        "--db-path", str(demo_pki / "micropki.db")
    ])
    
    # 5. Start Servers
    print("\n--- 5. Starting Repo and OCSP Servers ---")
    repo_proc = subprocess.Popen(micropki_cmd + [
        "repo", "serve",
        "--host", "127.0.0.1", "--port", "8080",
        "--db-path", str(demo_pki / "micropki.db"),
        "--cert-dir", str(demo_pki / "certs")
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    ocsp_proc = subprocess.Popen(micropki_cmd + [
        "ocsp", "serve",
        "--host", "127.0.0.1", "--port", "8081",
        "--db-path", str(demo_pki / "micropki.db"),
        "--responder-cert", str(demo_pki / "certs" / "Demo_OCSP_Responder.cert.pem"),
        "--responder-key", str(demo_pki / "certs" / "Demo_OCSP_Responder.key.pem"),
        "--ca-cert", str(demo_pki / "certs" / "intermediate.cert.pem")
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print("Waiting for servers to start...")
    time.sleep(3)
    
    try:
        # 6. Perform Validation
        print("\n--- 6. Performing Certificate Validation (OCSP & CRL) ---")
        run_cmd(micropki_cmd + [
            "client", "validate",
            "--cert", str(demo_pki / "certs" / "demo.example.com.cert.pem"),
            "--untrusted", str(demo_pki / "certs" / "intermediate.cert.pem"),
            "--trusted", str(demo_pki / "certs" / "ca.cert.pem"),
            "--ocsp", "--ocsp-url", "http://127.0.0.1:8081",
            "--mode", "full"
        ])
        
        # 7. Revoke Certificate
        print("\n--- 7. Revoking Server Certificate ---")
        # Need to find the serial. It's stored in the DB, or we can use check-revoked if we know it.
        # Let's list certs
        res = run_cmd(micropki_cmd + [
            "ca", "list-certs", "--db-path", str(demo_pki / "micropki.db"), "--format", "json"
        ])
        import json
        certs = json.loads(res.stdout)
        server_serial = None
        for c in certs:
            if "demo.example.com" in c["subject"]:
                server_serial = c["serial_hex"]
                break
        
        if server_serial:
            run_cmd(micropki_cmd + [
                "ca", "revoke", server_serial,
                "--reason", "keyCompromise",
                "--db-path", str(demo_pki / "micropki.db"),
                "--force"
            ])
            
            # 8. Demonstrate revoked status
            print("\n--- 8. Demonstrating Revoked Status ---")
            res_val = run_cmd(micropki_cmd + [
                "client", "validate",
                "--cert", str(demo_pki / "certs" / "demo.example.com.cert.pem"),
                "--untrusted", str(demo_pki / "certs" / "intermediate.cert.pem"),
                "--trusted", str(demo_pki / "certs" / "ca.cert.pem"),
                "--ocsp", "--ocsp-url", "http://127.0.0.1:8081",
                "--mode", "full"
            ], check=False)
            
            if res_val.returncode != 0:
                print("[PASS] Validation failed as expected for revoked certificate.")
            else:
                print("[FAIL] Validation succeeded but should have failed!")
                sys.exit(1)
        else:
            print("[FAIL] Could not find server certificate serial.")
            sys.exit(1)
            
        # 9. Audit log integrity
        print("\n--- 9. Verifying Audit Log Integrity ---")
        run_cmd(micropki_cmd + [
            "audit", "verify",
            "--log-file-path", str(demo_pki / "audit" / "audit.log"),
            "--chain-file", str(demo_pki / "audit" / "chain.dat")
        ])
        
    finally:
        print("\n--- 10. Stopping Servers ---")
        repo_proc.terminate()
        ocsp_proc.terminate()
        repo_proc.wait()
        ocsp_proc.wait()
        print("Servers stopped.")
        print("\n[SUCCESS] Demo completed successfully!")

if __name__ == "__main__":
    main()
