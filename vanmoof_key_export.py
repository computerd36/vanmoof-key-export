#!/usr/bin/env python3
"""Export the Bluetooth encryption key of VanMoof S3/X3 bikes from a VanMoof account.

Usage: python3 vanmoof_key_export.py [--email EMAIL] [--json FILE [--raw]]
"""

import argparse
import base64
import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

__version__ = "1.0.0"

# Static key shipped with the official app, identical for every user.
# It has been public for years and is not a secret.
API_KEY = "fcb38d47-f14b-30cf-843b-26283f6a5819"

# my.vanmoof.com no longer resolves; it stays as a fallback in case it comes back.
BASE_URLS = (
    "https://api.vanmoof-api.com/v8",
    "https://my.vanmoof.com/api/v8",
)

TIMEOUT = 20
USER_AGENT = f"vanmoof-key-export/{__version__}"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_BIKES = 2


class ExportError(Exception):
    pass


class AuthError(ExportError):
    pass


class ConnectionFailed(ExportError):
    pass


class HTTPStatusError(ExportError):
    def __init__(self, url, code):
        super().__init__(f"{url} returned HTTP {code}.")
        self.code = code


def is_connection_error(exc):
    # Network-level failures (DNS, refused, unreachable, timeout) justify trying
    # the other host. TLS errors are OSErrors too, but the other host would fail
    # the same way.
    return isinstance(exc, OSError) and not isinstance(exc, ssl.SSLError)


def request_json(method, url, headers):
    headers = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
        "Api-Key": API_KEY,
        **headers,
    }
    data = b"" if method == "POST" else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        raise HTTPStatusError(url, e.code) from None
    except urllib.error.URLError as e:
        if is_connection_error(e.reason):
            raise ConnectionFailed(str(e.reason)) from None
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            detail = getattr(e.reason, "verify_message", None) or e.reason
            raise ExportError(
                f"TLS certificate verification failed for {url}: {detail}.\n"
                "Most likely your Python cannot find any CA certificates. With the python.org "
                "installer on macOS, run 'Install Certificates.command' from the "
                "Python folder in Applications, or start the script with "
                "SSL_CERT_FILE=$(python3 -m certifi)."
            ) from None
        raise ExportError(f"Request to {url} failed: {e.reason}") from None
    except OSError as e:
        # Raised directly (not wrapped in URLError) while reading the response.
        if is_connection_error(e):
            raise ConnectionFailed(str(e) or type(e).__name__) from None
        raise ExportError(f"Request to {url} failed: {e}") from None

    try:
        return json.loads(body)
    except ValueError:
        raise ExportError(f"{url} did not return valid JSON.") from None


def authenticate(base_url, email, password):
    credentials = base64.b64encode(f"{email}:{password}".encode()).decode()
    try:
        data = request_json(
            "POST",
            f"{base_url}/authenticate",
            {"Authorization": f"Basic {credentials}"},
        )
    except HTTPStatusError as e:
        if e.code in (401, 403):
            raise AuthError(
                f"The VanMoof API rejected the login (HTTP {e.code}). "
                "Check your email address and password."
            ) from None
        raise
    token = data.get("token") if isinstance(data, dict) else None
    if not token:
        raise ExportError("Login response did not contain a token.")
    return token


def login(email, password):
    """Return (base_url, token) for the first host that can be reached."""
    failures = []
    for base_url in BASE_URLS:
        try:
            return base_url, authenticate(base_url, email, password)
        except ConnectionFailed as e:
            failures.append(f"{base_url}: {e}")
    raise ExportError(
        "Could not reach the VanMoof API.\n  " + "\n  ".join(failures)
    )


def get_bikes(base_url, token):
    data = request_json(
        "GET",
        f"{base_url}/getCustomerData?includeBikeDetails",
        {"Authorization": f"Bearer {token}"},
    )
    try:
        bikes = data["data"].get("bikeDetails") or []
    except (KeyError, TypeError, AttributeError):
        bikes = None
    if not isinstance(bikes, list):
        raise ExportError("Unexpected response format from getCustomerData.")
    return bikes


def summarize(bike):
    key = bike.get("key") or {}
    return {
        "name": bike.get("name"),
        "modelName": bike.get("modelName"),
        "frameNumber": bike.get("frameNumber"),
        "macAddress": bike.get("macAddress"),
        "encryptionKey": key.get("encryptionKey"),
        "userKeyId": key.get("userKeyId"),
    }


def format_bike(summary):
    def show(value):
        return "-" if value is None or value == "" else str(value)

    rows = [
        ("Name", summary["name"]),
        ("Model", summary["modelName"]),
        ("Frame number", summary["frameNumber"]),
        ("encryptionKey", summary["encryptionKey"]),
        ("userKeyId", summary["userKeyId"]),
        ("Account MAC", summary["macAddress"]),
    ]
    lines = [f"  {label + ':':<15}{show(value)}" for label, value in rows]
    if not summary["encryptionKey"]:
        lines.append("  No encryption key on the account for this bike (not an S3/X3?).")
    return "\n".join(lines)


def write_json(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    # The mode passed to os.open only applies to newly created files.
    os.chmod(path, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Export the Bluetooth encryption key of VanMoof S3/X3 bikes "
        "from your VanMoof account.",
    )
    parser.add_argument("--email", help="account email (prompted if omitted)")
    parser.add_argument(
        "--json", metavar="FILE", help="also write the result to FILE (mode 0600)"
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="with --json, write the full bikeDetails instead of the summary",
    )
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    if args.raw and not args.json:
        parser.error("--raw requires --json")
    return args


def run(args):
    email = args.email or input("VanMoof account email: ").strip()
    if not email:
        raise ExportError("No email address given.")
    password = getpass.getpass("Password: ")
    if not password:
        raise ExportError("No password given.")

    base_url, token = login(email, password)
    bikes = get_bikes(base_url, token)

    if not bikes:
        print("Logged in, but there are no bikes on this account.")
        return EXIT_NO_BIKES

    summaries = [summarize(bike) for bike in bikes]
    print(f"Found {len(bikes)} bike(s):\n")
    for summary in summaries:
        print(format_bike(summary))
        print()
    print(
        "Keep the encryption key private. Anyone who has it can unlock and "
        "control your bike over Bluetooth."
    )
    print(
        "Note: the account MAC may differ from the address the bike advertises "
        "over Bluetooth."
    )

    if args.json:
        try:
            write_json(args.json, bikes if args.raw else summaries)
        except OSError as e:
            raise ExportError(f"Could not write {args.json}: {e.strerror or e}") from None
        print(f"\nWrote {args.json}")

    return EXIT_OK


def main(argv=None):
    args = parse_args(argv)
    try:
        return run(args)
    except ExportError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_ERROR
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
