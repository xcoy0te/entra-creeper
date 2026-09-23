"""Offline unit tests for entra-creeper. No network access required."""
import importlib.util
import os
import unittest
from pathlib import Path

# Load the hyphenated single-file script as a module.
_PATH = Path(__file__).resolve().parent.parent / "entra-creeper.py"
_spec = importlib.util.spec_from_file_location("entra_creeper", _PATH)
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)


class ClassifyTests(unittest.TestCase):
    def test_exists(self):
        self.assertEqual(m.classify({"IfExistsResult": 0}), ("valid", 0, "exists", False))

    def test_not_exist(self):
        self.assertEqual(m.classify({"IfExistsResult": 1}), ("invalid", 1, "not-exist", False))

    def test_other_idp_is_valid(self):
        self.assertEqual(m.classify({"IfExistsResult": 5})[0], "valid")

    def test_both_idp_is_valid(self):
        self.assertEqual(m.classify({"IfExistsResult": 6})[0], "valid")

    def test_code2_is_throttle_unknown(self):
        v, code, meaning, throttled = m.classify({"IfExistsResult": 2, "ThrottleStatus": 1})
        self.assertEqual(v, "unknown")
        self.assertTrue(throttled)

    def test_throttlestatus_flag(self):
        self.assertTrue(m.classify({"IfExistsResult": 0, "ThrottleStatus": 1})[3])

    def test_missing_json(self):
        self.assertEqual(m.classify(None), ("unknown", None, "no-json", False))

    def test_missing_code(self):
        self.assertEqual(m.classify({"foo": "bar"}), ("unknown", None, "no-code", False))


class EmailRegexTests(unittest.TestCase):
    def test_valid(self):
        for e in ["a@b.com", "john.doe@sub.example.co.uk", "x+y@z.io"]:
            self.assertRegex(e, m.EMAIL_RE)

    def test_invalid(self):
        for e in ["notanemail", "a@b", "@b.com", "a@", "a b@c.com", ""]:
            self.assertIsNone(m.EMAIL_RE.match(e))


class ReadEmailsTests(unittest.TestCase):
    def _args(self, path):
        class A:
            email = None
            file = path
            stdin = False
        return A()

    def test_dedupe_lowercase_and_skip_malformed(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("John@Target.com\njohn@target.com\n# comment\nbad-line\n\nsue@target.com\n")
            path = fh.name
        try:
            emails, skipped = m.read_emails(self._args(path))
            self.assertEqual(emails, ["john@target.com", "sue@target.com"])
            self.assertEqual(skipped, 1)  # 'bad-line'
        finally:
            os.unlink(path)


class CheckEmailTests(unittest.TestCase):
    """Exercise the request/retry logic with http_json mocked out."""

    def setUp(self):
        self._orig = m.http_json

    def tearDown(self):
        m.http_json = self._orig

    def _run(self, email="user@target.com", **kw):
        return m.check_email(
            email,
            opener_factory=lambda: object(),
            user_agent="ua",
            timeout=1,
            endpoint="https://example/GetCredentialType",
            throttle_retries=kw.pop("retries", 2),
            federated_domains=kw.pop("federated", set()),
            limiter=kw.pop("limiter", None),
        )

    def test_valid(self):
        m.http_json = lambda *a, **k: m.HttpResp(200, {"IfExistsResult": 0}, "", 0.0)
        self.assertEqual(self._run().verdict, "valid")

    def test_invalid(self):
        m.http_json = lambda *a, **k: m.HttpResp(200, {"IfExistsResult": 1}, "", 0.0)
        self.assertEqual(self._run().verdict, "invalid")

    def test_retries_then_succeeds(self):
        calls = {"n": 0}

        def flaky(*a, **k):
            calls["n"] += 1
            if calls["n"] < 2:
                return m.HttpResp(200, {"IfExistsResult": 2, "ThrottleStatus": 1}, "", 0.0)
            return m.HttpResp(200, {"IfExistsResult": 0}, "", 0.0)

        m.http_json = flaky
        r = self._run(retries=3, limiter=m.RateLimiter(0))  # cooldown 0 = no real sleeping
        self.assertEqual(r.verdict, "valid")
        self.assertEqual(calls["n"], 2)

    def test_stays_unknown_when_always_throttled(self):
        m.http_json = lambda *a, **k: m.HttpResp(200, {"IfExistsResult": 2, "ThrottleStatus": 1}, "", 0.0)
        r = self._run(retries=1, limiter=m.RateLimiter(0))
        self.assertEqual(r.verdict, "unknown")
        self.assertTrue(r.throttled)

    def test_http_429_is_throttle(self):
        m.http_json = lambda *a, **k: m.HttpResp(429, None, "", 1.0)
        r = self._run(retries=0, limiter=m.RateLimiter(0))
        self.assertEqual(r.verdict, "unknown")
        self.assertTrue(r.throttled)

    def test_federated_note_on_valid(self):
        m.http_json = lambda *a, **k: m.HttpResp(200, {"IfExistsResult": 0}, "", 0.0)
        r = self._run(federated={"target.com"})
        self.assertTrue(r.federated)
        self.assertIn("federated", r.note)

    def test_request_failure_is_unknown(self):
        def boom(*a, **k):
            raise OSError("net down")

        m.http_json = boom
        r = self._run(retries=0)
        self.assertEqual(r.verdict, "unknown")
        self.assertIn("request-failed", r.note)


class RateLimiterTests(unittest.TestCase):
    def test_disabled_when_zero(self):
        rl = m.RateLimiter(0)
        self.assertEqual(rl.trip(), 0.0)
        rl.wait()  # returns immediately

    def test_trip_extends_pause(self):
        rl = m.RateLimiter(2.0, quiet=True)
        cd = rl.trip()
        self.assertGreaterEqual(cd, 2.0)

    def test_retry_after_respected(self):
        rl = m.RateLimiter(1.0, quiet=True)
        cd = rl.trip(retry_after=10.0)
        self.assertGreaterEqual(cd, 10.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
