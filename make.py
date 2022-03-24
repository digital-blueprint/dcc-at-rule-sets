#!/usr/bin/env python3

import argparse
import os
import glob
import json
import shutil
from datetime import datetime, timezone

DIR = os.path.dirname(os.path.realpath(__file__))
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
    not_valid_before = cert.not_valid_before.astimezone(timezone.utc)
    not_valid_after = cert.not_valid_after.astimezone(timezone.utc)
    if not (not_valid_before <= NOW <= not_valid_after):
        raise Exception(
            f"cert not valid re time: "
            f"{not_valid_before.isoformat()} <= {NOW} <= {not_valid_after.isoformat()}")
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
    valid_from = datetime.fromtimestamp(signature_content[5], tz=timezone.utc)
    valid_until = datetime.fromtimestamp(signature_content[4], tz=timezone.utc)

    async with httpx.AsyncClient() as client:
        r = await client.get(f"{base_url}/{thing}")
        r.raise_for_status()
        content = r.content
    if checksum != hashlib.sha256(content).digest():
        raise Exception()
    if not (valid_from <= NOW <= valid_until):
        raise Exception(
            f"trust data not valid re time: "
            f"{valid_from.isoformat()} <= {NOW} <= {valid_until.isoformat()}")

    # We can trust the content, so decode it
    return cbor2.loads(content)


async def do_build(args):
    import jinja2

    target = os.path.abspath(args.target)

    rulesets = os.path.join(DIR, "rulesets")
    sets = os.path.join(target, "sets")
    names = []
    for name in os.listdir(rulesets):
        names.append(name)
        source = os.path.join(rulesets, name)
        rules = []
        for path in sorted(glob.glob(source + "/**/*.json", recursive=True)):
            with open(path, "rb") as h:
                decoded = json.loads(h.read())
                rules.append({
                    "i": decoded["Identifier"],
                    "r": json.dumps(decoded),
                })
        os.makedirs(sets, exist_ok=True)
        with open(os.path.join(sets, name + ".json"), "w", encoding="utf-8") as h:
            h.write(json.dumps({"r": rules}, indent=2))

    with open("index.tmpl", "r", encoding="utf-8") as h:
        with open(os.path.join(target, "index.html"), "w", encoding="utf-8") as h2:
            tmpl = jinja2.Template(h.read())
            h2.write(tmpl.render(names=sorted(names)))


async def do_format(args):
    rulesets = os.path.join(DIR, "rulesets")
    for name in os.listdir(rulesets):
        source = os.path.join(rulesets, name)
        for path in sorted(glob.glob(source + "/**/*.json", recursive=True)):
            with open(path, "rb") as h:
                sorted_rules = json.dumps(
                    json.loads(h.read()), sort_keys=True, indent=4, ensure_ascii=False)
            with open(path, "w", encoding="utf-8") as h:
                h.write(sorted_rules)


async def import_at(args):
    for is_test, name in [(True, "AT-TEST"), (False, "AT-PROD")]:
        target = os.path.join(DIR, "rulesets", name)
        shutil.rmtree(target, ignore_errors=True)
        os.makedirs(target, exist_ok=True)

        prod_rules = await fetch_austria_data_and_verify(is_test, "rules")
        to_import = []
        for entry in prod_rules["r"]:
            decoded = json.loads(entry["r"])
            if decoded["Country"] != "AT" or decoded["Engine"] != "CERTLOGIC":
                continue
            to_import.append(decoded)

        def get_unique_name(decoded):
            for e in to_import:
                if e is not decoded and e["Identifier"] == decoded["Identifier"] and e["Region"] == decoded["Region"]:
                    return decoded["Identifier"] + "-" + decoded["Version"]
            return decoded["Identifier"]

        for decoded in to_import:
            sub = os.path.join(target, decoded["Region"])
            os.makedirs(sub, exist_ok=True)
            json_target = os.path.join(sub, get_unique_name(decoded) + ".json")
            assert not os.path.exists(json_target)
            with open(json_target, "w", encoding="utf-8") as h:
                h.write(json.dumps(decoded, sort_keys=True, indent=4, ensure_ascii=False))


def main(argv):
    parser = argparse.ArgumentParser(description="Manage rule sets", allow_abbrev=False)

    async def show_help(*x):
        parser.print_help()

    parser.set_defaults(func=show_help)
    subparser = parser.add_subparsers(title="subcommands")

    sub = subparser.add_parser("import-at", help="Import the official Austria rule sets")
    sub.set_defaults(func=import_at)

    sub = subparser.add_parser("format", help="Re-format/sort all JSON rule sets")
    sub.set_defaults(func=do_format)

    sub = subparser.add_parser("build", help="Build the web directory")
    sub.add_argument("target")
    sub.set_defaults(func=do_build)

    args = parser.parse_args(argv[1:])
    asyncio.run(args.func(args))


if __name__ == "__main__":
    import asyncio
    import sys
    main(sys.argv)
