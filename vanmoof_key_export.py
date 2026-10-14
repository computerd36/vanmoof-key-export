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


def request_json(method, url, headers):
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT, **headers}
    data = b"" if method == "POST" else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise AuthError(
                f"The VanMoof API rejected the login (HTTP {e.code}). "
                "Check your email address and password."
            ) from None
        raise ExportError(f"{url} returned HTTP {e.code}.") from None
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            # Not a connectivity problem, the other host would fail the same way.
            detail = getattr(e.reason, "verify_message", None) or e.reason
            raise ExportError(
                f"TLS certificate verification failed for {url}: {detail}.\n"
                "Most likely your Python cannot find any CA certificates. With the python.org "
                "installer on macOS, run 'Install Certificates.command' from the "
                "Python folder in Applications, or start the script with "
                "SSL_CERT_FILE=$(python3 -m certifi)."
            ) from None
        raise ConnectionFailed(str(e.reason)) from None
    except OSError as e:
        # Timeouts and connection resets while reading the response.
        raise ConnectionFailed(str(e) or type(e).__name__) from None

    try:
        return json.loads(body)
    except ValueError:
        raise ExportError(f"{url} did not return valid JSON.") from None


def authenticate(base_url, email, password):
    credentials = base64.b64encode(f"{email}:{password}".encode()).decode()
    data = request_json(
        "POST",
        f"{base_url}/authenticate",
        {"Api-Key": API_KEY, "Authorization": f"Basic {credentials}"},
    )
    token = data.get("token") if isinstance(data, dict) else None
    if not token:
        raise ExportError("Login response did not contain a token.")
    return token


def login(email, password, base_urls=BASE_URLS):
    """Return (base_url, token) for the first host that can be reached."""
    failures = []
    for base_url in base_urls:
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
        {"Api-Key": API_KEY, "Authorization": f"Bearer {token}"},
    )
    try:
        bikes = data["data"].get("bikeDetails") or []
    except (KeyError, TypeError, AttributeError):
        raise ExportError("Unexpected response format from getCustomerData.") from None
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
    del password
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
