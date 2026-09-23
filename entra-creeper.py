#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
entra-creeper - Office 365 / Microsoft Entra ID email-address validation.

A modernized, dependency-free successor to LMGsec's o365creeper. It confirms
whether an email address maps to a real Microsoft account by inspecting the
unauthenticated `GetCredentialType` response - it never submits a password, so
it does not trigger sign-in logging or Smart Lockout.

Design goal: do ONE thing - decide exists / does-not-exist / unknown - as
accurately as possible. Key accuracy features:
  * Correct validity logic - IfExistsResult 0/5/6 are valid, not just 0.
  * Adaptive, shared throttle handling - all workers cool down together when
    Microsoft starts throttling (honoring Retry-After), so concurrency does not
    poison results.
  * Automatic retry pass - addresses left `unknown` due to throttling are
    re-checked at the end, so the final answer is as clean as possible.
  * Per-domain realm (getuserrealm) pre-check: skips non-Microsoft domains and
    warns on federated domains where GetCredentialType is unreliable.

Plus quality-of-life: JSON/CSV output, resume, stdin input, proxy rotation,
FireProx support, User-Agent rotation, graceful Ctrl-C.

AUTHORIZED USE ONLY. Run this against domains/accounts you own or are explicitly
permitted to test. You are responsible for complying with all applicable laws,
contracts, and provider terms.

License: MIT
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import os
import random
import re
import signal
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional, Tuple

__version__ = "1.1.0"

GETCREDENTIALTYPE_URL = "https://login.microsoftonline.com/common/GetCredentialType"
GETUSERREALM_URL = "https://login.microsoftonline.com/getuserrealm.srf"

# IfExistsResult values returned by GetCredentialType.
# -1 Unknown, 0 Exists, 1 NotExist, 2 Throttled, 4 Error,
# 5 ExistsInOtherMicrosoftIDP, 6 ExistsInBothIDPs.
IFEXISTS_MEANING = {
    -1: "unknown",
    0: "exists",
    1: "not-exist",
    2: "throttled",
    4: "error",
    5: "exists-other-idp",
    6: "exists-both-idp",
}
VALID_CODES = {0, 5, 6}
INVALID_CODES = {1}
THROTTLE_CODES = {2}

# Deliberately permissive - matches real-world addresses, rejects obvious junk.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

HttpResp = namedtuple("HttpResp", ["status", "json", "text", "retry_after"])

# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GREY = "\033[90m"

    @classmethod
    def disable(cls) -> None:
        for name in ("RESET", "BOLD", "RED", "GREEN", "YELLOW", "BLUE", "CYAN", "GREY"):
            setattr(cls, name, "")


_print_lock = threading.Lock()


def log(msg: str, quiet: bool = False) -> None:
    if quiet:
        return
    with _print_lock:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def make_ssl_context(insecure: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def build_opener(proxy: Optional[str], ctx: ssl.SSLContext) -> urllib.request.OpenerDirector:
    handlers: List[urllib.request.BaseHandler] = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))  # ignore env proxies unless asked
    return urllib.request.build_opener(*handlers)


def _parse_retry_after(value: Optional[str]) -> float:
    if not value:
        return 0.0
    try:
        return max(0.0, float(value))  # delta-seconds form
    except (TypeError, ValueError):
        return 0.0  # HTTP-date form is rare here; adaptive cooldown covers it


def http_json(
    opener: urllib.request.OpenerDirector,
    url: str,
    *,
    method: str = "GET",
    body: Optional[dict] = None,
    user_agent: str,
    timeout: float,
) -> HttpResp:
    """Return an HttpResp. Raises only on transport-level failure."""
    data = None
    headers = {
        "User-Agent": user_agent,
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=UTF-8"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    retry_after = 0.0
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = resp.getcode()
            retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else ""
        status = e.code
        retry_after = _parse_retry_after(e.headers.get("Retry-After") if e.headers else None)
    parsed: Optional[dict] = None
    if raw:
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            parsed = None
    return HttpResp(status, parsed, raw, retry_after)


# ---------------------------------------------------------------------------
# Adaptive rate limiter (shared across workers)
# ---------------------------------------------------------------------------


class RateLimiter:
    """When Microsoft throttles, pause ALL workers together, backing off
    exponentially and honoring Retry-After. A clean response resets the streak.
    Set base_cooldown <= 0 to disable adaptive behavior entirely."""

    def __init__(self, base_cooldown: float, cap: float = 60.0, quiet: bool = False) -> None:
        self.base = base_cooldown
        self.cap = cap
        self.quiet = quiet
        self._lock = threading.Lock()
        self._pause_until = 0.0
        self._streak = 0
        self._last_notice = 0.0

    def wait(self) -> None:
        if self.base <= 0:
            return
        while True:
            with self._lock:
                remaining = self._pause_until - time.time()
            if remaining <= 0:
                return
            time.sleep(min(remaining, 2.0) + random.random() * 0.2)

    def trip(self, retry_after: float = 0.0) -> float:
        """Record a throttle event; extend the shared pause. Returns cooldown."""
        if self.base <= 0:
            return 0.0
        with self._lock:
            self._streak += 1
            cd = min(self.base * (2 ** (self._streak - 1)), self.cap)
            cd = max(cd, retry_after)
            self._pause_until = max(self._pause_until, time.time() + cd)
            notice = time.time() - self._last_notice > 3.0
            if notice:
                self._last_notice = time.time()
        if notice:
            log(C.YELLOW + "[!] Throttling detected - cooling down %.0fs (all workers)" % cd + C.RESET,
                quiet=self.quiet)
        return cd

    def ok(self) -> None:
        if self.base <= 0:
            return
        with self._lock:
            self._streak = 0


# ---------------------------------------------------------------------------
# Realm (tenant) awareness
# ---------------------------------------------------------------------------


def check_realm(
    opener: urllib.request.OpenerDirector, domain: str, user_agent: str, timeout: float
) -> dict:
    qs = urllib.parse.urlencode({"login": "test@" + domain, "json": "1"})
    url = GETUSERREALM_URL + "?" + qs
    out = {"domain": domain, "namespace": "Unknown", "brand": None, "is_o365": False}
    try:
        resp = http_json(opener, url, user_agent=user_agent, timeout=timeout)
    except Exception:
        return out
    if not resp.json:
        return out
    ns = resp.json.get("NameSpaceType", "Unknown")
    out["namespace"] = ns
    out["brand"] = resp.json.get("FederationBrandName")
    out["is_o365"] = ns in ("Managed", "Federated")
    return out


# ---------------------------------------------------------------------------
# Core email check
# ---------------------------------------------------------------------------


class Result:
    __slots__ = ("email", "verdict", "code", "meaning", "throttled", "federated", "note")

    def __init__(self, email: str) -> None:
        self.email = email
        self.verdict = "unknown"  # valid | invalid | unknown
        self.code: Optional[int] = None
        self.meaning = ""
        self.throttled = False
        self.federated = False
        self.note = ""

    def as_dict(self) -> dict:
        return {
            "email": self.email,
            "verdict": self.verdict,
            "ifexists_code": self.code,
            "meaning": self.meaning,
            "throttled": self.throttled,
            "federated": self.federated,
            "note": self.note,
        }


def classify(parsed: Optional[dict]) -> Tuple[str, Optional[int], str, bool]:
    """Map a GetCredentialType response to (verdict, code, meaning, throttled)."""
    if not parsed:
        return "unknown", None, "no-json", False
    throttled = str(parsed.get("ThrottleStatus", 0)) not in ("0", "None")
    code = parsed.get("IfExistsResult")
    try:
        code = int(code)
    except (TypeError, ValueError):
        return "unknown", None, "no-code", throttled
    meaning = IFEXISTS_MEANING.get(code, "code-%s" % code)
    if code in THROTTLE_CODES:
        return "unknown", code, meaning, True
    if code in VALID_CODES:
        return "valid", code, meaning, throttled
    if code in INVALID_CODES:
        return "invalid", code, meaning, throttled
    return "unknown", code, meaning, throttled


def check_email(
    email: str,
    *,
    opener_factory: Callable[[], urllib.request.OpenerDirector],
    user_agent: str,
    timeout: float,
    endpoint: str,
    throttle_retries: int,
    federated_domains: set,
    limiter: Optional[RateLimiter] = None,
) -> Result:
    res = Result(email)
    domain = email.split("@", 1)[1].lower() if "@" in email else ""
    res.federated = domain in federated_domains
    body = {"username": email, "isOtherIdpSupported": True}

    attempt = 0
    backoff = 1.0
    while True:
        if limiter:
            limiter.wait()
        opener = opener_factory()
        try:
            resp = http_json(
                opener, endpoint, method="POST", body=body, user_agent=user_agent, timeout=timeout
            )
        except Exception as e:
            if attempt < throttle_retries:
                attempt += 1
                time.sleep(backoff + random.random())
                backoff *= 2
                continue
            res.verdict = "unknown"
            res.note = "request-failed: %s" % type(e).__name__
            return res

        verdict, code, meaning, throttled = classify(resp.json)
        http_throttled = resp.status == 429 or resp.retry_after > 0
        throttled = throttled or http_throttled
        res.verdict, res.code, res.meaning, res.throttled = verdict, code, meaning, throttled
        if http_throttled and verdict != "valid" and verdict != "invalid":
            res.verdict = "unknown"

        if throttled:
            if limiter:
                limiter.trip(resp.retry_after)
            if attempt < throttle_retries:
                attempt += 1
                if not limiter:
                    time.sleep(backoff + random.random())
                    backoff *= 2
                continue
        else:
            if limiter:
                limiter.ok()
        break

    if res.throttled and res.verdict == "unknown":
        res.note = "throttled - result unreliable, will retry / use --fireprox"
    if res.federated and res.verdict == "valid":
        res.note = "federated domain - GetCredentialType may report all users as valid"
    return res


# ---------------------------------------------------------------------------
# Input / output
# ---------------------------------------------------------------------------


def read_emails(args) -> Tuple[List[str], int]:
    """Return (unique valid-format emails, skipped_malformed_count)."""
    seen = set()
    out: List[str] = []
    skipped = 0

    def add(line: str) -> None:
        nonlocal skipped
        e = line.strip()
        if not e or e.startswith("#"):
            return
        e = e.lower()
        if not EMAIL_RE.match(e):
            skipped += 1
            return
        if e in seen:
            return
        seen.add(e)
        out.append(e)

    if args.email:
        add(args.email)
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                add(line)
    if args.stdin or (not args.email and not args.file and not sys.stdin.isatty()):
        for line in sys.stdin:
            add(line)
    return out, skipped


def load_resume(path: str) -> set:
    done = set()
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                e = line.strip().lower()
                if e:
                    done.add(e)
    return done


class OutputWriter:
    """Streams valid emails to the plaintext file as they are found (crash-safe)."""

    def __init__(self, path: Optional[str]) -> None:
        self._lock = threading.Lock()
        self._written = set()
        self._fh = open(path, "a", encoding="utf-8") if path else None

    def write_valid(self, email: str) -> None:
        if not self._fh:
            return
        with self._lock:
            if email in self._written:
                return
            self._written.add(email)
            self._fh.write(email + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()


def write_json(path: str, results: List[Result]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([r.as_dict() for r in results], fh, indent=2)


def write_csv(path: str, results: List[Result]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["email", "verdict", "ifexists_code", "meaning", "throttled", "federated", "note"],
        )
        w.writeheader()
        for r in results:
            w.writerow(r.as_dict())


# ---------------------------------------------------------------------------
# Banner / args
# ---------------------------------------------------------------------------

BANNER = (
    C.CYAN + C.BOLD + "  entra-creeper " + C.RESET + C.GREY + "v%s" % __version__ + C.RESET + "\n"
    + C.GREY + "  O365 / Entra ID email validation - no login attempts, authorized use only\n" + C.RESET
)


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="entra-creeper",
        description="Validate Office 365 / Entra ID email addresses via GetCredentialType (no password submitted).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  entra-creeper.py -e john@target.com
  entra-creeper.py -f emails.txt -o valid.txt -w 20 --delay 0.3 --jitter 0.4
  cat emails.txt | entra-creeper.py --json out.json --check-domains
  entra-creeper.py -f emails.txt --proxy-file proxies.txt --random-agent
  entra-creeper.py -f emails.txt --fireprox https://abc.execute-api.us-east-1.amazonaws.com/fireprox
""",
    )
    src = p.add_argument_group("input")
    src.add_argument("-e", "--email", help="single email address to validate")
    src.add_argument("-f", "--file", help="file with one email address per line")
    src.add_argument("--stdin", action="store_true", help="force reading addresses from stdin")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", help="append valid emails to this file (plaintext, streamed)")
    out.add_argument("--json", dest="json_out", help="write full results (all verdicts) to JSON file")
    out.add_argument("--csv", dest="csv_out", help="write full results (all verdicts) to CSV file")
    out.add_argument("--resume", action="store_true", help="skip addresses already present in --output")
    out.add_argument("-q", "--quiet", action="store_true", help="only print valid addresses to stdout")
    out.add_argument("-v", "--verbose", action="store_true", help="print every verdict, including invalid")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    out.add_argument("--no-banner", action="store_true", help="suppress the banner")

    net = p.add_argument_group("network / OPSEC")
    net.add_argument("-w", "--workers", type=int, default=10, help="concurrent workers (default 10)")
    net.add_argument("-t", "--timeout", type=float, default=30.0, help="per-request timeout seconds (default 30)")
    net.add_argument("--delay", type=float, default=0.0, help="base delay before each request (seconds)")
    net.add_argument("--jitter", type=float, default=0.0, help="random extra delay 0..N added to --delay")
    net.add_argument("--throttle-retries", type=int, default=3, help="per-address retries on throttle/error (default 3)")
    net.add_argument("--retry-pass", type=int, default=1,
                     help="extra full passes over throttled 'unknown' addresses (default 1, 0 disables)")
    net.add_argument("--cooldown", type=float, default=5.0,
                     help="base adaptive cooldown seconds when throttled; 0 disables (default 5)")
    net.add_argument("--proxy", help="single proxy URL, e.g. http://127.0.0.1:8080")
    net.add_argument("--proxy-file", help="file of proxy URLs to rotate through")
    net.add_argument("--fireprox", help="FireProx base URL to front GetCredentialType (rotates source IP)")
    net.add_argument("--user-agent", help="fixed User-Agent string")
    net.add_argument("--random-agent", action="store_true", help="rotate through a pool of browser User-Agents")
    net.add_argument("--insecure", action="store_true", help="skip TLS verification (for intercepting proxies)")

    enr = p.add_argument_group("enrichment")
    enr.add_argument("--check-domains", action="store_true",
                     help="probe each domain's realm first; skip non-Microsoft domains and flag federated ones")

    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p.parse_args(argv)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    if args.no_color or not sys.stderr.isatty():
        C.disable()
    # Rebuild banner after color decision.
    banner = (
        C.CYAN + C.BOLD + "  entra-creeper " + C.RESET + C.GREY + "v%s" % __version__ + C.RESET + "\n"
        + C.GREY + "  O365 / Entra ID email validation - no login attempts, authorized use only\n" + C.RESET
    )
    if not args.no_banner and not args.quiet:
        log(banner)

    emails, skipped = read_emails(args)
    if skipped:
        log(C.GREY + "[*] Skipped %d malformed line(s)." % skipped + C.RESET, quiet=args.quiet)
    if not emails:
        log(C.RED + "[!] No valid input addresses. Use -e, -f, or pipe via stdin. See -h." + C.RESET)
        return 2

    already = load_resume(args.output) if (args.resume and args.output) else set()
    if already:
        before = len(emails)
        emails = [e for e in emails if e not in already]
        log(C.GREY + "[*] Resume: skipping %d already-checked address(es)." % (before - len(emails)) + C.RESET,
            quiet=args.quiet)
    if not emails:
        log(C.YELLOW + "[*] Nothing left to check." + C.RESET, quiet=args.quiet)
        return 0

    ctx = make_ssl_context(args.insecure)

    # Proxy rotation.
    proxies: List[Optional[str]] = []
    if args.proxy_file:
        with open(args.proxy_file, "r", encoding="utf-8") as fh:
            proxies = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    elif args.proxy:
        proxies = [args.proxy]
    proxy_cycle = itertools.cycle(proxies) if proxies else None
    proxy_lock = threading.Lock()

    def next_proxy() -> Optional[str]:
        if not proxy_cycle:
            return None
        with proxy_lock:
            return next(proxy_cycle)

    def opener_factory() -> urllib.request.OpenerDirector:
        return build_opener(next_proxy(), ctx)

    def pick_agent() -> str:
        if args.user_agent:
            return args.user_agent
        if args.random_agent:
            return random.choice(USER_AGENTS)
        return USER_AGENTS[0]

    endpoint = GETCREDENTIALTYPE_URL
    if args.fireprox:
        endpoint = args.fireprox.rstrip("/") + "/common/GetCredentialType"
        log(C.GREY + "[*] Routing GetCredentialType through FireProx." + C.RESET, quiet=args.quiet)

    # Optional per-domain realm pre-check.
    federated_domains: set = set()
    if args.check_domains:
        realm_by_domain: Dict[str, dict] = {}
        domains = sorted({e.split("@", 1)[1].lower() for e in emails if "@" in e})
        log(C.BLUE + "[*] Checking %d domain(s) via getuserrealm..." % len(domains) + C.RESET, quiet=args.quiet)
        for d in domains:
            info = check_realm(build_opener(next_proxy(), ctx), d, pick_agent(), args.timeout)
            realm_by_domain[d] = info
            if info["namespace"] == "Federated":
                federated_domains.add(d)
                log(C.YELLOW + "    [~] %s : FEDERATED (%s) - results may be unreliable"
                    % (d, info.get("brand") or "?") + C.RESET, quiet=args.quiet)
            elif info["namespace"] == "Managed":
                log(C.GREEN + "    [+] %s : Managed (Microsoft-hosted)" % d + C.RESET, quiet=args.quiet)
            else:
                log(C.GREY + "    [-] %s : not a Microsoft tenant - skipping its addresses" % d + C.RESET,
                    quiet=args.quiet)
        skip_domains = {d for d, i in realm_by_domain.items() if not i["is_o365"]}
        if skip_domains:
            emails = [e for e in emails if e.split("@", 1)[1].lower() not in skip_domains]
    if not emails:
        log(C.YELLOW + "[*] No addresses on Microsoft-hosted domains to check." + C.RESET, quiet=args.quiet)
        return 0

    writer = OutputWriter(args.output)
    results: Dict[str, Result] = {}
    results_lock = threading.Lock()
    order = list(emails)
    stop = threading.Event()
    limiter = RateLimiter(args.cooldown, quiet=args.quiet)

    def handle_sigint(signum, frame):
        stop.set()
        log("\n" + C.YELLOW + "[!] Interrupted - finishing in-flight requests and flushing output..." + C.RESET)

    signal.signal(signal.SIGINT, handle_sigint)

    def worker(email: str, total: int, label: str) -> None:
        if stop.is_set():
            return
        if args.delay or args.jitter:
            time.sleep(args.delay + (random.random() * args.jitter if args.jitter else 0))
        r = check_email(
            email,
            opener_factory=opener_factory,
            user_agent=pick_agent(),
            timeout=args.timeout,
            endpoint=endpoint,
            throttle_retries=args.throttle_retries,
            federated_domains=federated_domains,
            limiter=limiter,
        )
        with results_lock:
            results[email] = r
            done = len(results)

        if r.verdict == "valid":
            writer.write_valid(r.email)
            extra = C.GREY + " (%s)" % r.meaning + C.RESET if r.meaning != "exists" else ""
            if r.note:
                extra += C.YELLOW + " [%s]" % r.note + C.RESET
            if args.quiet:
                with _print_lock:
                    print(r.email)
            else:
                log(C.GREEN + "[+] VALID  " + C.RESET + r.email + extra)
        elif r.verdict == "invalid":
            if args.verbose and not args.quiet:
                log(C.RED + "[-] invalid " + C.RESET + r.email)
        else:
            if not args.quiet:
                log(C.YELLOW + "[?] unknown " + C.RESET + r.email
                    + C.GREY + " (%s)" % (r.note or r.meaning) + C.RESET)

        if not args.quiet and not args.verbose and done % 25 == 0:
            log(C.GREY + "    ... %s %d/%d" % (label, done, total) + C.RESET)

    def run_pass(pass_emails: List[str], label: str) -> None:
        total = len(pass_emails)
        with results_lock:
            # Fresh accounting per pass for the progress counter.
            pass_done = {"n": 0}
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = [pool.submit(worker, e, total, label) for e in pass_emails]
            for f in futures:
                if stop.is_set():
                    break
                f.result()

    start = time.time()
    log(C.BLUE + "[*] Validating %d address(es) with %d worker(s)..." % (len(emails), args.workers) + C.RESET,
        quiet=args.quiet)
    try:
        run_pass(emails, "checked")
        # Retry passes over throttled 'unknown' addresses only.
        passes = max(0, args.retry_pass)
        for i in range(passes):
            if stop.is_set():
                break
            retry = [e for e, r in results.items() if r.verdict == "unknown" and r.throttled]
            if not retry:
                break
            log(C.BLUE + "[*] Retry pass %d/%d: re-checking %d throttled address(es)..."
                % (i + 1, passes, len(retry)) + C.RESET, quiet=args.quiet)
            time.sleep(min(args.cooldown * 2, 30) if args.cooldown > 0 else 2)
            run_pass(retry, "re-checked")
    finally:
        writer.close()

    ordered = [results[e] for e in order if e in results]
    if args.json_out:
        write_json(args.json_out, ordered)
    if args.csv_out:
        write_csv(args.csv_out, ordered)

    counters = {"valid": 0, "invalid": 0, "unknown": 0}
    for r in ordered:
        counters[r.verdict] = counters.get(r.verdict, 0) + 1

    if not args.quiet:
        elapsed = time.time() - start
        log("")
        log(C.BOLD + "=== Summary ===" + C.RESET)
        log(C.GREEN + "  valid  : %d" % counters["valid"] + C.RESET)
        log(C.RED + "  invalid: %d" % counters["invalid"] + C.RESET)
        log(C.YELLOW + "  unknown: %d" % counters["unknown"] + C.RESET)
        log(C.GREY + "  checked: %d in %.1fs" % (len(ordered), elapsed) + C.RESET)
        if args.output:
            log(C.GREY + "  valid addresses appended to %s" % args.output + C.RESET)
        if counters["unknown"]:
            log(C.YELLOW + "  note: 'unknown' verdicts remained throttled/errored - re-run later or use --fireprox."
                + C.RESET)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
