#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["certifi", "cryptography", "requests"]
# ///
r"""Build a CA bundle from the Windows cert store and wire it into the user
environment, so requests/boto3/aws-cli stop failing behind a TLS-inspecting
proxy. No admin rights needed.

    uv run corp_ca.py            # build bundle + set env vars
    uv run corp_ca.py --list     # show certs Windows has that certifi doesn't
    uv run corp_ca.py --test     # real HTTPS calls, no verify= param
    uv run corp_ca.py --revert   # remove the env vars

Env vars land in HKCU\Environment. RESTART THE PC afterwards - a new terminal
frequently isn't enough, because editors, Jupyter kernels and shells inherit the
environment their parent process was started with.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import os
import re
import ssl
import sys
import winreg
from ctypes import wintypes
from pathlib import Path

import certifi
from cryptography import x509

SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"
ENV_VARS = [
    "REQUESTS_CA_BUNDLE",  # requests
    "CURL_CA_BUNDLE",      # requests fallback, curl.exe
    "SSL_CERT_FILE",       # OpenSSL: urllib, httpx, aiohttp
    "AWS_CA_BUNDLE",       # aws cli, boto3
    "NODE_EXTRA_CA_CERTS", # node, npm
    "GIT_SSL_CAINFO",      # git
    "PIP_CERT",            # pip
]
TEST_URLS = ["https://www.google.com", "https://sts.amazonaws.com/"]
PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)

BUNDLE = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "corp-ca" / "corp-ca-bundle.pem"


def windows_certs() -> dict[bytes, str]:
    """{DER: PEM} from the Windows ROOT and CA stores, server-auth only."""
    out: dict[bytes, str] = {}
    for store in ("ROOT", "CA"):
        try:
            entries = ssl.enum_certificates(store)
        except Exception as exc:
            print(f"  ! {store}: {exc}")
            continue
        for der, encoding, trust in entries:
            if encoding != "x509_asn":
                continue
            if trust is not True and not (
                isinstance(trust, (set, frozenset, list, tuple)) and SERVER_AUTH_OID in trust
            ):
                continue
            out.setdefault(der, ssl.DER_cert_to_PEM_cert(der))
    return out


def pem_certs(data: bytes) -> dict[bytes, str]:
    out: dict[bytes, str] = {}
    for m in PEM_RE.finditer(data):
        try:
            der = base64.b64decode(b"".join(m.group(1).split()))
        except Exception:
            continue
        out.setdefault(der, ssl.DER_cert_to_PEM_cert(der))
    return out


def describe(der: bytes) -> str:
    try:
        cert = x509.load_der_x509_certificate(der)
        cn = next((a.value for a in cert.subject if a.oid.dotted_string == "2.5.4.3"), None)
        org = next((a.value for a in cert.subject if a.oid.dotted_string == "2.5.4.10"), None)
        return f"{cn or org or cert.subject.rfc4514_string()}  (expires {cert.not_valid_after_utc:%Y-%m-%d})"
    except Exception as exc:
        return f"<unparseable: {exc}>"


def build() -> dict[bytes, str]:
    """Write certifi + Windows store to BUNDLE. Returns the Windows-only extras."""
    public = pem_certs(Path(certifi.where()).read_bytes())
    local = windows_certs()
    merged = public | local
    extra = {d: p for d in local if (p := local[d]) and d not in public}

    BUNDLE.parent.mkdir(parents=True, exist_ok=True)
    BUNDLE.write_text(
        f"# certifi + Windows cert store, {len(merged)} certificates\n\n"
        + "".join(merged.values()),
        encoding="ascii",
    )
    print(f"{len(merged)} certs -> {BUNDLE}")
    print(f"  {len(public)} from certifi, {len(extra)} only in the Windows store")
    return extra


def broadcast() -> None:
    res = wintypes.DWORD()
    ctypes.windll.user32.SendMessageTimeoutW(
        0xFFFF, 0x001A, 0, ctypes.c_wchar_p("Environment"), 0x0002, 5000, ctypes.byref(res)
    )


def set_env(remove: bool = False) -> None:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE) as key:
        for var in ENV_VARS:
            if remove:
                try:
                    winreg.DeleteValue(key, var)
                    print(f"  removed {var}")
                except OSError:
                    print(f"  not set {var}")
            else:
                winreg.SetValueEx(key, var, 0, winreg.REG_SZ, str(BUNDLE))
                os.environ[var] = str(BUNDLE)
                print(f"  {var}")
    broadcast()
    if remove:
        return
    print(
        "\n*** RESTART YOUR PC NOW ***\n"
        "Running processes keep the environment they were launched with, so a new\n"
        "terminal is often not enough - editors and Jupyter kernels inherit from a\n"
        "parent that started earlier, and managed machines frequently ignore the\n"
        "broadcast this script just sent. A reboot is the reliable fix.\n"
        "\n"
        "After rebooting, confirm with:  python -c \"import os;print(os.environ['REQUESTS_CA_BUNDLE'])\""
    )


def test() -> int:
    import requests

    for var in ("REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "AWS_CA_BUNDLE"):
        os.environ[var] = str(BUNDLE)

    failed = 0
    for url in TEST_URLS:
        try:
            r = requests.get(url, timeout=20)  # no verify= param
            print(f"  ok    {url} -> {r.status_code}")
        except requests.exceptions.SSLError as exc:
            failed += 1
            print(f"  FAIL  {url} -> {exc}")
        except requests.RequestException as exc:
            print(f"  warn  {url} -> {type(exc).__name__} (not a TLS problem)")
    return failed


def main() -> int:
    if sys.platform != "win32":
        sys.exit("Windows only (needs ssl.enum_certificates).")

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true", help="show certs only present in the Windows store")
    ap.add_argument("--no-env", action="store_true", help="write the bundle but don't touch the environment")
    ap.add_argument("--test", action="store_true", help="make real HTTPS requests without verify=")
    ap.add_argument("--revert", action="store_true", help="delete the environment variables")
    args = ap.parse_args()

    if args.revert:
        set_env(remove=True)
        return 0

    extra = build()

    if args.list:
        print("\nWindows-only certs (your inspection root is in here):")
        for der in extra:
            print(f"  - {describe(der)}")

    if not args.no_env:
        print("\nSetting user environment variables:")
        set_env()

    if args.test:
        print("\nTesting:")
        return 1 if test() else 0
    return 0


def cli() -> None:
    """Console-script entry point. Wraps main() because setuptools/hatch entry
    points discard return values, which would lose the exit code."""
    raise SystemExit(main())


if __name__ == "__main__":
    cli()
