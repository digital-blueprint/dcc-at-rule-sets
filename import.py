#!/usr/bin/env python3

import os
import json
from datetime import datetime, timezone

NOW = datetime.now(timezone.utc)

AUSTRIA_API_CERT_PROD = b"""\
-----BEGIN CERTIFICATE-----
MIIB1DCCAXmgAwIBAgIKAXnM+Z3eG2QgVzAKBggqhkjOPQQDAjBEMQswCQYDVQQG
EwJBVDEPMA0GA1UECgwGQk1TR1BLMQwwCgYDVQQFEwMwMDExFjAUBgNVBAMMDUFU
IERHQyBDU0NBIDEwHhcNMjEwNjAyMTM0NjIxWhcNMjIwNzAyMTM0NjIxWjBFMQsw
CQYDVQQGEwJBVDEPMA0GA1UECgwGQk1TR1BLMQ8wDQYDVQQFEwYwMDEwMDExFDAS
BgNVBAMMC0FUIERHQyBUTCAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEl2tm
d16CBHXwcBN0r1Uy+CmNW/b2V0BNP85y5N3JZeo/8l9ey/jIe5mol9fFcGTk9bCk
8zphVo0SreHa5aWrQKNSMFAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBRTwp6d
cDGcPUB6IwdDja/a3ncM0TAfBgNVHSMEGDAWgBQfIqwcZRYptMGYs2Nvv90Jnbt7
ezAKBggqhkjOPQQDAgNJADBGAiEAlR0x3CRuQV/zwHTd2R9WNqZMabXv5XqwHt72
qtgnjRgCIQCZHIHbCvlgg5uL8ZJQzAxLavqF2w6uUxYVrvYDj2Cqjw==
-----END CERTIFICATE-----"""

AUSTRIA_API_CERT_TEST = b"""\
-----BEGIN CERTIFICATE-----
MIIB6zCCAZGgAwIBAgIKAXmEuohlRbR2qzAKBggqhkjOPQQDAjBQMQswCQYDVQQG
EwJBVDEPMA0GA1UECgwGQk1TR1BLMQowCAYDVQQLDAFRMQwwCgYDVQQFEwMwMDEx
FjAUBgNVBAMMDUFUIERHQyBDU0NBIDEwHhcNMjEwNTE5MTMwNDQ3WhcNMjIwNjE5
MTMwNDQ3WjBRMQswCQYDVQQGEwJBVDEPMA0GA1UECgwGQk1TR1BLMQowCAYDVQQL
DAFRMQ8wDQYDVQQFEwYwMDEwMDExFDASBgNVBAMMC0FUIERHQyBUTCAxMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE29KpT1eIKsy5Jx3J0xpPLW+fEBF7ma9943/j
4Z+o1TytLVok9cWjsdasWCS/zcRyAh7HBL+oyMWdFBOWENCQ76NSMFAwDgYDVR0P
AQH/BAQDAgeAMB0GA1UdDgQWBBQYmsL5sXTdMCyW4UtP5BMxq+UAVzAfBgNVHSME
GDAWgBR2sKi2xkUpGC1Cr5ehwL0hniIsJzAKBggqhkjOPQQDAgNIADBFAiBse17k
F5F43q9mRGettRDLprASrxsDO9XxUUp3ObjcWQIhALfUWnserGEPiD7Pa25tg9lj
wkrqDrMdZHZ39qb+Jf/E
-----END CERTIFICATE-----"""


async def fetch_austria_data_and_verify(test: bool, thing: str):
    # See https://github.com/Federal-Ministry-of-Health-AT/green-pass-overview
    # for details. This is Austria specific, but uses the same technologies as the rest

    if test:
        base_url = "https://dgc-trusttest.qr.gv.at"
        cert = AUSTRIA_API_CERT_TEST
    else:
        base_url = "https://dgc-trust.qr.gv.at"
        cert = AUSTRIA_API_CERT_PROD

    # First we fetch the signature
    # (which is a COSE message where the payload is the checksum of the real content)
    import httpx
    from cose.messages import CoseMessage
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{base_url}/{thing}sig")
        r.raise_for_status()
        signature = r.content
    cose_msg = CoseMessage.decode(signature)

    # Use the official certificate to create a COSE key
    from cryptography import x509
    from cose.keys import EC2Key
    cert = x509.load_pem_x509_certificate(cert)
    public_key = cert.public_key()
    x = public_key.public_numbers().x.to_bytes(32, "big")
    y = public_key.public_numbers().y.to_bytes(32, "big")
    cose_key = EC2Key(crv='P_256', x=x, y=y, optional_params={'ALG': 'ES256'})

    # Set the key and verify the signature
    cose_msg.key = cose_key
    cose_msg.verify_signature()

    # Load the content and check that the checksum matches
    # and that it is still valid
    import hashlib
    import cbor2
    signature_content = cbor2.loads(cose_msg.payload)
    checksum = signature_content[2]
    valid_from = signature_content[5]
    valid_until = signature_content[4]

    async with httpx.AsyncClient() as client:
        r = await client.get(f"{base_url}/{thing}")
        r.raise_for_status()
        content = r.content
    if checksum != hashlib.sha256(content).digest():
        raise Exception()
    if not (valid_from <= NOW.timestamp() <= valid_until):
        raise Exception("trust data not valid re time")

    # We can trust the content, so decode it
    return cbor2.loads(content)


async def main(argv):
    target = os.path.abspath(argv[1])
    os.makedirs(target, exist_ok=True)
    test_rules = await fetch_austria_data_and_verify(True, "rules")
    with open(os.path.join(target, "AT-TEST.json"), "w", encoding="utf-8") as h:
        h.write(json.dumps(test_rules, indent=2))
    prod_rules = await fetch_austria_data_and_verify(False, "rules")
    with open(os.path.join(target, "AT-PROD.json"), "w", encoding="utf-8") as h:
        h.write(json.dumps(prod_rules, indent=2))


if __name__ == "__main__":
    import asyncio
    import sys
    asyncio.run(main(sys.argv))
