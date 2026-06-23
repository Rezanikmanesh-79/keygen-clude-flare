#!/usr/bin/env python3
"""
اسکریپت گرفتن گواهی Let's Encrypt با DNS-01 validation از طریق Cloudflare API.

این اسکریپت را روی کامپیوتر خودتان (نه روی سرور ایرانی) اجرا کنید، چون
اینترنت خانه شما به Cloudflare/Let's Encrypt دسترسی بهتری دارد.

خروجی: دو فایل cert.pem و key.pem که باید با scp به سرور منتقل کنید.

نصب پیش‌نیاز:
    pip install cryptography requests

اجرا:
    python3 get_cert.py
"""

import base64
import hashlib
import json
import os
import sys
import time

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

# ===================== تنظیمات =====================
DOMAIN = "meet.shinigami.ir"
EMAIL = "rezanikmanesh@gmail.com"
CF_API_TOKEN = ""  # clude flare toeken

ACME_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
# برای تست اول با staging امتحان کنید تا مطمئن شوید همه‌چیز کار می‌کند:
# ACME_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"

OUTPUT_DIR = "./jitsi-cert-output"
# =====================================================

CF_API_BASE = "https://api.cloudflare.com/client/v4"
CF_HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json",
}


def cf_get_zone_id(domain):
    """پیدا کردن zone id کلودفلر برای دامنه ریشه"""
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        resp = requests.get(
            f"{CF_API_BASE}/zones", headers=CF_HEADERS, params={"name": candidate}
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("result"):
            return data["result"][0]["id"], candidate
    raise RuntimeError(f"zone برای دامنه {domain} در کلودفلر پیدا نشد")


def cf_create_txt(zone_id, name, content):
    resp = requests.post(
        f"{CF_API_BASE}/zones/{zone_id}/dns_records",
        headers=CF_HEADERS,
        json={"type": "TXT", "name": name, "content": content, "ttl": 60},
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"ساخت رکورد TXT شکست خورد: {data}")
    return data["result"]["id"]


def cf_delete_record(zone_id, record_id):
    resp = requests.delete(
        f"{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}", headers=CF_HEADERS
    )
    resp.raise_for_status()


def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def jwk_from_key(key):
    pub = key.public_key().public_numbers()
    n = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")
    e = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "n": b64(n), "e": b64(e)}


def jwk_thumbprint(jwk):
    canon = json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode()
    return b64(hashlib.sha256(canon).digest())


class AcmeClient:
    def __init__(self, directory_url, account_key):
        self.account_key = account_key
        self.jwk = jwk_from_key(account_key)
        self.directory = requests.get(directory_url).json()
        self.kid = None
        self._nonce = None

    def _new_nonce(self):
        resp = requests.head(self.directory["newNonce"])
        return resp.headers["Replay-Nonce"]

    def _sign(self, url, payload):
        nonce = self._nonce or self._new_nonce()
        protected = {"alg": "RS256", "url": url, "nonce": nonce}
        if self.kid:
            protected["kid"] = self.kid
        else:
            protected["jwk"] = self.jwk

        protected_b64 = b64(json.dumps(protected).encode())
        payload_b64 = b64(json.dumps(payload).encode()) if payload != "" else ""
        signing_input = f"{protected_b64}.{payload_b64}".encode()

        signature = self.account_key.sign(
            signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
        return {
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64(signature),
        }

    def post(self, url, payload):
        body = self._sign(url, payload)
        resp = requests.post(
            url, json=body, headers={"Content-Type": "application/jose+json"}
        )
        self._nonce = resp.headers.get("Replay-Nonce")
        if resp.status_code >= 400:
            raise RuntimeError(f"ACME error {resp.status_code}: {resp.text}")
        return resp

    def register_account(self):
        resp = self.post(
            self.directory["newAccount"],
            {"termsOfServiceAgreed": True, "contact": [f"mailto:{EMAIL}"]},
        )
        self.kid = resp.headers["Location"]
        return resp.json()

    def new_order(self, domain):
        resp = self.post(
            self.directory["newOrder"],
            {"identifiers": [{"type": "dns", "value": domain}]},
        )
        return resp.json(), resp.headers["Location"]

    def get_authorization(self, authz_url):
        resp = self.post(authz_url, "")
        return resp.json()

    def respond_challenge(self, challenge_url):
        return self.post(challenge_url, {})

    def poll(self, url, key="status", target="valid", timeout=90):
        start = time.time()
        while time.time() - start < timeout:
            resp = self.post(url, "")
            data = resp.json()
            if data.get(key) == target:
                return data
            if data.get(key) == "invalid":
                raise RuntimeError(f"اعتبارسنجی شکست خورد: {data}")
            time.sleep(3)
        raise TimeoutError(f"poll تایم‌اوت شد روی {url}")

    def finalize(self, finalize_url, csr_der):
        resp = self.post(finalize_url, {"csr": b64(csr_der)})
        return resp.json()

    def download_cert(self, cert_url):
        nonce = self._nonce or self._new_nonce()
        protected = {"alg": "RS256", "url": cert_url, "nonce": nonce, "kid": self.kid}
        protected_b64 = b64(json.dumps(protected).encode())
        payload_b64 = ""
        signing_input = f"{protected_b64}.{payload_b64}".encode()
        signature = self.account_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        body = {"protected": protected_b64, "payload": payload_b64, "signature": b64(signature)}
        resp = requests.post(
            cert_url, json=body, headers={"Content-Type": "application/jose+json"}
        )
        self._nonce = resp.headers.get("Replay-Nonce")
        return resp.text


def main():
    if "PUT_YOUR" in CF_API_TOKEN:
        print("لطفاً اول CF_API_TOKEN را در بالای فایل تنظیم کنید.")
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("[1/8] پیدا کردن zone کلودفلر...")
    zone_id, zone_name = cf_get_zone_id(DOMAIN)
    print(f"   zone پیدا شد: {zone_name} ({zone_id})")

    print("[2/8] ساخت account key و ثبت‌نام حساب ACME...")
    account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = AcmeClient(ACME_DIRECTORY_URL, account_key)
    client.register_account()

    print("[3/8] ساخت order برای دامنه...")
    order, order_url = client.new_order(DOMAIN)

    record_ids = []
    try:
        print("[4/8] گرفتن challenge و ساخت رکورد TXT...")
        for authz_url in order["authorizations"]:
            authz = client.get_authorization(authz_url)
            dns_challenge = next(c for c in authz["challenges"] if c["type"] == "dns-01")

            token = dns_challenge["token"]
            thumbprint = jwk_thumbprint(client.jwk)
            key_authz = f"{token}.{thumbprint}"
            txt_value = b64(hashlib.sha256(key_authz.encode()).digest())

            record_name = f"_acme-challenge.{DOMAIN}"
            print(f"   در حال ساخت TXT: {record_name} = {txt_value}")
            record_id = cf_create_txt(zone_id, record_name, txt_value)
            record_ids.append(record_id)

            print("   صبر می‌کنیم تا DNS منتشر شود (۲۰ ثانیه)...")
            time.sleep(20)

            print("[5/8] اعلام آمادگی به Let's Encrypt برای چک کردن چالش...")
            client.respond_challenge(dns_challenge["url"])

            print("   در انتظار تایید اعتبارسنجی...")
            client.poll(authz_url, key="status", target="valid")
            print("   اعتبارسنجی موفق بود.")

        print("[6/8] ساخت کلید خصوصی دامنه و CSR...")
        domain_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)]))
            .sign(domain_key, hashes.SHA256())
        )
        csr_der = csr.public_bytes(serialization.Encoding.DER)

        print("[7/8] فاینالایز کردن order و دریافت گواهی...")
        client.finalize(order["finalize"], csr_der)
        finalize_data = client.poll(order_url, key="status", target="valid", timeout=60)
        cert_pem = client.download_cert(finalize_data["certificate"])

        print("[8/8] ذخیره فایل‌ها...")
        key_pem = domain_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        cert_path = os.path.join(OUTPUT_DIR, "cert.pem")
        key_path = os.path.join(OUTPUT_DIR, "key.pem")

        with open(cert_path, "w") as f:
            f.write(cert_pem)
        with open(key_path, "wb") as f:
            f.write(key_pem)

        print()
        print("=" * 60)
        print("گواهی با موفقیت صادر شد!")
        print(f"  گواهی: {cert_path}")
        print(f"  کلید:  {key_path}")
        print()
        print("حالا این دو فایل را به سرور ایرانی‌تان منتقل کنید، مثلا:")
        print(f"  scp {cert_path} user@your-server-ip:/path/to/jitsi-meet-cfg/web/keys/cert.crt")
        print(f"  scp {key_path} user@your-server-ip:/path/to/jitsi-meet-cfg/web/keys/cert.key")
        print("=" * 60)

    finally:
        print("\nپاک کردن رکوردهای TXT موقت از کلودفلر...")
        for rid in record_ids:
            try:
                cf_delete_record(zone_id, rid)
            except Exception as e:
                print(f"   هشدار: نتوانستم رکورد {rid} را پاک کنم: {e}")


if __name__ == "__main__":
    main()