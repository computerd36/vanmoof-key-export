import base64
import io
import json
import os
import socket
import ssl
import stat
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vanmoof_key_export as vke  # noqa: E402

PRIMARY, FALLBACK = vke.BASE_URLS

BIKE = {
    "name": "My S3",
    "modelName": "S3",
    "frameNumber": "ASY1234567",
    "macAddress": "F8:8A:5E:00:11:22",
    "bikeId": 123456,
    "key": {"encryptionKey": "00112233445566778899aabbccddeeff", "userKeyId": 7},
}


class FakeResponse:
    def __init__(self, data):
        self._body = json.dumps(data).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(url, code):
    return urllib.error.HTTPError(url, code, "error", {}, io.BytesIO(b""))


class FakeApi:
    """Stand-in for urlopen that answers based on the request URL."""

    def __init__(self, bikes=(BIKE,), unreachable=(), auth_status=None):
        self.bikes = list(bikes)
        self.unreachable = unreachable
        self.auth_status = auth_status
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        url = req.full_url
        if any(url.startswith(base) for base in self.unreachable):
            raise urllib.error.URLError(socket.gaierror(8, "nodename nor servname provided"))
        if url.endswith("/authenticate"):
            if self.auth_status:
                raise http_error(url, self.auth_status)
            return FakeResponse({"token": "test-token"})
        if "/getCustomerData" in url:
            return FakeResponse({"data": {"bikeDetails": self.bikes}})
        raise AssertionError(f"unexpected request to {url}")


class LoginTests(unittest.TestCase):
    def test_uses_primary_host(self):
        api = FakeApi()
        with mock.patch("urllib.request.urlopen", api):
            base, token = vke.login("me@example.com", "secret")
        self.assertEqual(base, PRIMARY)
        self.assertEqual(token, "test-token")
        self.assertEqual(len(api.requests), 1)

    def test_sends_api_key_and_basic_auth(self):
        api = FakeApi()
        with mock.patch("urllib.request.urlopen", api):
            vke.login("me@example.com", "secret")
        req = api.requests[0]
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.get_header("Api-key"), vke.API_KEY)
        expected = base64.b64encode(b"me@example.com:secret").decode()
        self.assertEqual(req.get_header("Authorization"), f"Basic {expected}")

    def test_falls_back_on_connection_error(self):
        api = FakeApi(unreachable=(PRIMARY,))
        with mock.patch("urllib.request.urlopen", api):
            base, token = vke.login("me@example.com", "secret")
        self.assertEqual(base, FALLBACK)
        self.assertEqual(token, "test-token")
        self.assertEqual(len(api.requests), 2)

    def test_falls_back_on_timeout(self):
        calls = []

        def urlopen(req, timeout=None):
            calls.append(req.full_url)
            if req.full_url.startswith(PRIMARY):
                raise socket.timeout("timed out")
            return FakeResponse({"token": "t"})

        with mock.patch("urllib.request.urlopen", urlopen):
            base, _ = vke.login("me@example.com", "secret")
        self.assertEqual(base, FALLBACK)
        self.assertEqual(len(calls), 2)

    def test_all_hosts_unreachable(self):
        api = FakeApi(unreachable=vke.BASE_URLS)
        with mock.patch("urllib.request.urlopen", api):
            with self.assertRaises(vke.ExportError) as ctx:
                vke.login("me@example.com", "secret")
        self.assertIn("Could not reach", str(ctx.exception))

    def test_certificate_error_stops_without_fallback(self):
        calls = []

        def urlopen(req, timeout=None):
            calls.append(req.full_url)
            err = ssl.SSLCertVerificationError(1, "certificate verify failed")
            err.verify_message = "unable to get local issuer certificate"
            raise urllib.error.URLError(err)

        with mock.patch("urllib.request.urlopen", urlopen):
            with self.assertRaises(vke.ExportError) as ctx:
                vke.login("me@example.com", "secret")
        self.assertNotIsInstance(ctx.exception, vke.ConnectionFailed)
        self.assertIn("Install Certificates.command", str(ctx.exception))
        self.assertEqual(len(calls), 1)

    def test_401_stops_without_fallback(self):
        api = FakeApi(auth_status=401)
        with mock.patch("urllib.request.urlopen", api):
            with self.assertRaises(vke.AuthError) as ctx:
                vke.login("me@example.com", "wrong")
        self.assertIn("email address and password", str(ctx.exception))
        self.assertEqual(len(api.requests), 1)

    def test_403_is_auth_error(self):
        api = FakeApi(auth_status=403)
        with mock.patch("urllib.request.urlopen", api):
            with self.assertRaises(vke.AuthError):
                vke.login("me@example.com", "wrong")

    def test_other_http_error_does_not_fall_back(self):
        api = FakeApi(auth_status=500)
        with mock.patch("urllib.request.urlopen", api):
            with self.assertRaises(vke.ExportError) as ctx:
                vke.login("me@example.com", "secret")
        self.assertNotIsInstance(ctx.exception, vke.AuthError)
        self.assertEqual(len(api.requests), 1)


class GetBikesTests(unittest.TestCase):
    def test_returns_bike_details(self):
        api = FakeApi()
        with mock.patch("urllib.request.urlopen", api):
            bikes = vke.get_bikes(PRIMARY, "test-token")
        self.assertEqual(bikes, [BIKE])
        req = api.requests[0]
        self.assertEqual(req.full_url, f"{PRIMARY}/getCustomerData?includeBikeDetails")
        self.assertEqual(req.get_header("Authorization"), "Bearer test-token")

    def test_empty_bike_list(self):
        api = FakeApi(bikes=[])
        with mock.patch("urllib.request.urlopen", api):
            self.assertEqual(vke.get_bikes(PRIMARY, "test-token"), [])

    def test_unexpected_format(self):
        with mock.patch("urllib.request.urlopen", lambda req, timeout=None: FakeResponse({"oops": 1})):
            with self.assertRaises(vke.ExportError):
                vke.get_bikes(PRIMARY, "test-token")


class SummaryTests(unittest.TestCase):
    def test_extracts_fields(self):
        self.assertEqual(
            vke.summarize(BIKE),
            {
                "name": "My S3",
                "modelName": "S3",
                "frameNumber": "ASY1234567",
                "macAddress": "F8:8A:5E:00:11:22",
                "encryptionKey": "00112233445566778899aabbccddeeff",
                "userKeyId": 7,
            },
        )

    def test_missing_key(self):
        summary = vke.summarize({"name": "Other", "modelName": "S5", "key": None})
        self.assertIsNone(summary["encryptionKey"])
        self.assertIsNone(summary["userKeyId"])
        self.assertIn("No encryption key", vke.format_bike(summary))


class MainTests(unittest.TestCase):
    def run_main(self, argv, api):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("urllib.request.urlopen", api), \
                mock.patch("getpass.getpass", return_value="secret"), \
                mock.patch("builtins.input", return_value="me@example.com"), \
                redirect_stdout(out), redirect_stderr(err):
            code = vke.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_success_prints_key(self):
        code, out, _ = self.run_main([], FakeApi())
        self.assertEqual(code, vke.EXIT_OK)
        self.assertIn("00112233445566778899aabbccddeeff", out)
        self.assertIn("ASY1234567", out)
        self.assertIn("Keep the encryption key private", out)
        self.assertNotIn("secret", out)

    def test_no_bikes_exit_code(self):
        code, out, _ = self.run_main(["--email", "me@example.com"], FakeApi(bikes=[]))
        self.assertEqual(code, vke.EXIT_NO_BIKES)
        self.assertIn("no bikes", out)

    def test_wrong_credentials_exit_code(self):
        code, _, err = self.run_main([], FakeApi(auth_status=401))
        self.assertEqual(code, vke.EXIT_ERROR)
        self.assertIn("rejected the login", err)
        self.assertNotIn("Traceback", err)

    def test_unreachable_exit_code(self):
        code, _, err = self.run_main([], FakeApi(unreachable=vke.BASE_URLS))
        self.assertEqual(code, vke.EXIT_ERROR)
        self.assertIn("Could not reach", err)

    def test_raw_requires_json(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                vke.main(["--raw"])
        self.assertEqual(ctx.exception.code, 2)


class JsonExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "keys.json")

    def tearDown(self):
        self.tmp.cleanup()

    def run_export(self, *extra):
        with mock.patch("urllib.request.urlopen", FakeApi()), \
                mock.patch("getpass.getpass", return_value="secret"), \
                redirect_stdout(io.StringIO()):
            return vke.main(["--email", "me@example.com", "--json", self.path, *extra])

    def mode(self):
        return stat.S_IMODE(os.stat(self.path).st_mode)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_new_file_is_0600(self):
        self.assertEqual(self.run_export(), vke.EXIT_OK)
        self.assertEqual(self.mode(), 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_existing_file_is_tightened_to_0600(self):
        with open(self.path, "w") as f:
            f.write("old")
        os.chmod(self.path, 0o644)
        self.run_export()
        self.assertEqual(self.mode(), 0o600)

    def test_summary_content(self):
        self.run_export()
        with open(self.path) as f:
            data = json.load(f)
        self.assertEqual(data, [vke.summarize(BIKE)])

    def test_raw_content(self):
        self.run_export("--raw")
        with open(self.path) as f:
            data = json.load(f)
        self.assertEqual(data, [BIKE])

    def test_unwritable_path(self):
        self.path = os.path.join(self.tmp.name, "missing-dir", "keys.json")
        with redirect_stderr(io.StringIO()) as err:
            code = self.run_export()
        self.assertEqual(code, vke.EXIT_ERROR)
        self.assertIn("Could not write", err.getvalue())


if __name__ == "__main__":
    unittest.main()
