"""Security headers checker.

Fetches one page of a website (a single normal GET request, like a browser) and grades the security headers
it sends: HTTPS/HSTS, Content-Security-Policy, clickjacking protection, MIME sniffing, referrer and
permissions policies, cookie flags, and information leaks such as server versions.

Only check sites you own or are allowed to test. It sends one request and never tries to break anything.

Usage:
    python3 tools/header_checker.py https://example.com
    python3 tools/header_checker.py --test        # runs the built-in tests (no network)
"""
import re
import sys
import urllib.error
import urllib.request

PASS, WARN, FAIL = "✅", "⚠️ ", "❌"


def check(url: str, headers: dict, cookies: list) -> list:
    """Returns (status, header, message, points) rows. `headers` keys are lower-case."""
    rows = []
    h = headers.get

    def add(status, name, msg, points):
        rows.append((status, name, msg, points if status == PASS else points // 2 if status == WARN else 0, points))

    # HTTPS + HSTS
    if not url.startswith("https://"):
        add(FAIL, "HTTPS", "the site is not using HTTPS: everything can be read on the network", 20)
    else:
        hsts = h("strict-transport-security", "")
        age = int(re.search(r"max-age=(\d+)", hsts).group(1)) if re.search(r"max-age=(\d+)", hsts) else 0
        if age >= 15_552_000:
            add(PASS, "Strict-Transport-Security", f"HTTPS forced for {age // 86400} days", 20)
        elif hsts:
            add(WARN, "Strict-Transport-Security", f"max-age is only {age // 86400} days (use at least 180)", 20)
        else:
            add(FAIL, "Strict-Transport-Security", "missing: browsers may still try plain http first", 20)

    # CSP
    csp = h("content-security-policy", "")
    if not csp:
        add(FAIL, "Content-Security-Policy", "missing: injected scripts (XSS) would run", 25)
    else:
        script = re.search(r"script-src([^;]*)", csp) or re.search(r"default-src([^;]*)", csp)
        src = script.group(1) if script else ""
        weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:", "https:") if w in src.split()]
        if "'unsafe-inline'" in weak and ("'nonce-" in src or "'sha" in src):
            weak.remove("'unsafe-inline'")  # ignored by modern browsers when a nonce/hash is present
        if weak:
            add(WARN, "Content-Security-Policy", "present, but scripts allow " + ", ".join(weak), 25)
        else:
            add(PASS, "Content-Security-Policy", "present, no unsafe script sources", 25)

    # Clickjacking
    if "frame-ancestors" in csp or h("x-frame-options", "").upper() in ("DENY", "SAMEORIGIN"):
        add(PASS, "Clickjacking", "can't be hidden inside another site's frame", 10)
    else:
        add(FAIL, "Clickjacking", "no X-Frame-Options or frame-ancestors: the page can be framed", 10)

    add(PASS if h("x-content-type-options", "").lower() == "nosniff" else FAIL, "X-Content-Type-Options",
        "nosniff" if h("x-content-type-options") else "missing: browsers may guess file types", 10)
    rp = h("referrer-policy", "").lower()
    add(PASS if rp and rp not in ("unsafe-url", "no-referrer-when-downgrade") else WARN if rp else FAIL, "Referrer-Policy",
        rp or "missing: full addresses (with private ids) may leak to other sites", 5)
    add(PASS if h("permissions-policy") else WARN, "Permissions-Policy",
        "set" if h("permissions-policy") else "missing: camera, microphone and location aren't restricted", 5)
    add(PASS if h("cross-origin-opener-policy") else WARN, "Cross-Origin-Opener-Policy",
        h("cross-origin-opener-policy") or "missing: other sites that open this one can reach its window", 5)

    # Cookies
    if cookies:
        bad = [c.split("=", 1)[0] for c in cookies
               if not ("secure" in c.lower() and "httponly" in c.lower() and "samesite" in c.lower())]
        add(WARN if bad else PASS, "Cookies", f"missing Secure/HttpOnly/SameSite on: {', '.join(bad)}" if bad
            else f"{len(cookies)} cookie(s) with Secure, HttpOnly and SameSite", 10)
    else:
        add(PASS, "Cookies", "none set on this page", 10)

    # Information leaks
    leaks = [f"{k}: {h(k)}" for k in ("server", "x-powered-by", "x-aspnet-version") if h(k) and re.search(r"\d", h(k))]
    add(WARN if leaks else PASS, "Version leaks", "; ".join(leaks) + " (helps attackers pick exploits)" if leaks
        else "no software versions shown", 5)
    return rows


def grade(rows) -> tuple:
    got, total = sum(r[3] for r in rows), sum(r[4] for r in rows)
    pct = round(100 * got / total)
    letter = "A+" if pct >= 95 else "A" if pct >= 85 else "B" if pct >= 70 else "C" if pct >= 55 else "D" if pct >= 40 else "F"
    return pct, letter


def fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "header-checker/1.0 (learning project)"})
    try:
        r = urllib.request.urlopen(req, timeout=60)  # only http(s) urls reach here; 60 s lets sleeping free servers wake
    except urllib.error.HTTPError as e:
        r = e  # 4xx/5xx pages still have headers worth checking
    headers = {k.lower(): v for k, v in r.headers.items()}
    return r.geturl(), headers, r.headers.get_all("Set-Cookie") or []


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--test":
        return run_tests()
    url = argv[0] if re.match(r"^https?://", argv[0]) else "https://" + argv[0]
    try:
        final, headers, cookies = fetch(url)
    except (urllib.error.URLError, OSError) as e:
        print(f"Could not reach {url}: {getattr(e, 'reason', e)}")
        return 1
    rows = check(final, headers, cookies)
    pct, letter = grade(rows)
    print(f"\nSecurity headers for {final}\n")
    for status, name, msg, *_ in rows:
        print(f"  {status} {name:28} {msg}")
    print(f"\n  Grade: {letter} ({pct}/100)\n")
    return 0


def run_tests() -> int:
    strong = {"strict-transport-security": "max-age=31536000; includeSubDomains",
              "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'",
              "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin",
              "permissions-policy": "camera=()", "cross-origin-opener-policy": "same-origin", "server": "cloudflare"}
    assert grade(check("https://a.test", strong, ["sid=1; Secure; HttpOnly; SameSite=Lax"])) == (100, "A+")
    weak = check("http://a.test", {"server": "Apache/2.4.29 (Ubuntu)", "x-powered-by": "PHP/7.2.1"}, ["sid=1; path=/"])
    assert grade(weak)[1] == "F"
    assert any(r[1] == "Version leaks" and "PHP/7.2.1" in r[2] for r in weak)
    loose = dict(strong, **{"content-security-policy": "script-src 'self' 'unsafe-inline' https:"})
    assert any(r[1] == "Content-Security-Policy" and r[0] == WARN for r in check("https://a.test", loose, []))
    print("All header checker tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
