#!/usr/bin/env python3
"""A client that parses the challenge page but never runs its scripts.

Used by scripts/edge-challenge-noscript-smoke.sh against real OpenResty. For
each host it GETs the challenge page, reads every value the page exposes as
text (hidden inputs, button values, aria-label, element text, inline script
constants), waits out any countdown it can read, and POSTs the form back the
way a scraper would. It reports per host whether any attempt got a 303 (the
pass cookie), as one JSON object on stdout.

  edge-challenge-scraper.py PORT HOST:MODE [HOST:MODE ...]

With --solve it plays the browser instead (what the page script does): solves
the proof of work from the form's data-pow-* attributes, takes the puzzle
answer from the smoke's test-only admin endpoint, and runs the named cases:

  edge-challenge-scraper.py --solve PORT ADMIN_PORT HOST:MODE:CASE[,CASE...] ...

--pow FILE prints the proof of work for a saved challenge page.
"""
import concurrent.futures
import hashlib
import html.parser
import http.client
import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
import zlib

USER_AGENT = "cdnca-noscript-scraper/1.0"


class Page(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inputs = []
        self.buttons = []
        self.labels = []
        self.text = []
        self.scripts = []
        self.action = None
        self._script = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("aria-label"):
            self.labels.append(attrs["aria-label"])
        if attrs.get("alt"):
            self.labels.append(attrs["alt"])
        if tag == "form" and self.action is None:
            self.action = attrs.get("action")
        elif tag == "input":
            self.inputs.append(attrs)
        elif tag == "button":
            self.buttons.append(attrs)
        elif tag in ("script", "style"):
            self._script = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._script is not None:
            self.scripts.append("".join(self._script))
            self._script = None

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)
        else:
            self.text.append(data)


def request(port, host, method, path, body=None, cookie=None, user_agent=USER_AGENT, raw=False):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=15)
    headers = {"Host": host, "User-Agent": user_agent, "Accept": "text/html"}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if cookie:
        headers["Cookie"] = cookie
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = response.read()
    if not raw:
        payload = payload.decode("utf-8", "replace")
    result = (response.status, dict((k.lower(), v) for k, v in response.getheaders()), payload)
    connection.close()
    return result


def numbers(text):
    return [int(value) for value in re.findall(r"(?<![0-9A-Za-z])([0-9]{1,3})(?![0-9])", text)]


def guesses(mode, page):
    """Every response a page-reading script would try for this mode."""
    visible = " ".join(page.text)
    scripts = " ".join(page.scripts)
    found = []
    for field in page.inputs + page.buttons:
        if field.get("name") == "response" and field.get("value"):
            found.append(field["value"])
    if mode == "slider":
        for source in (visible, scripts):
            match = re.search(r"目标位置[^0-9]*([0-9]{1,3})", source)
            if match:
                found.append(match.group(1))
        match = re.search(r"\btarget\s*=\s*([0-9]{1,3})", scripts)
        if match:
            found.append(match.group(1))
    elif mode == "captcha":
        for source in page.labels + [visible]:
            found.extend(re.findall(r"\b([0-9A-Z]{6})\b", source.upper()))
    found.append("wait")
    unique = []
    for value in found:
        if value not in unique:
            unique.append(value)
    return unique


def countdown(page, mode):
    """The longest wait the page text or scripts announce (seconds)."""
    waits = [0]
    for source in page.text + page.scripts + [b.get("value", "") for b in page.buttons]:
        for match in re.finditer(r"(?:等待|seconds\s*=|wait\s*=)\s*([0-9]{1,2})", source):
            waits.append(int(match.group(1)))
    if mode == "delay":
        waits.append(5)
    return max(waits)


def attempt(port, host, mode, index):
    # Every attempt needs its own nonce, so read the guess off this fresh page.
    status, _, body = request(port, host, "GET", "/scrape?mode=" + mode)
    if status != 200:
        return {"guess": index, "get_status": status}
    page = Page()
    page.feed(body)
    started = time.monotonic()
    options = guesses(mode, page)
    guess = options[min(index, len(options) - 1)]
    values = {}
    for field in page.inputs:
        if field.get("name") and field.get("type", "text") == "hidden":
            values[field["name"]] = field.get("value", "")
    values["response"] = guess
    # Wait as long as the page says (plus slack), as a patient scraper would.
    pause = countdown(page, mode) + 0.4
    if guess == "wait":
        pause = max(pause, 6)
    time.sleep(max(0.3, pause - (time.monotonic() - started)))
    action = page.action or "/.cdnca/challenge/verify"
    status, headers, _ = request(port, host, "POST", action, urllib.parse.urlencode(values))
    return {"guess": guess, "status": status, "cookie": "set-cookie" in headers}


def scrape(port, host, mode):
    status, _, body = request(port, host, "GET", "/scrape?mode=" + mode)
    if status != 200:
        return {"host": host, "mode": mode, "passed": False, "error": "challenge page status %d" % status}
    page = Page()
    page.feed(body)
    tries = [attempt(port, host, mode, index) for index in range(len(guesses(mode, page)))]
    passed = any(t.get("status") == 303 and t.get("cookie") for t in tries)
    return {"host": host, "mode": mode, "passed": passed, "attempts": tries}


def solve_pow(salt_hex, target_hex, difficulty):
    salt = bytes.fromhex(salt_hex)
    for counter in range(2 ** difficulty):
        if hashlib.sha256(salt + str(counter).encode()).hexdigest() == target_hex:
            return counter
    raise RuntimeError("no proof of work in range")


def check_png(data):
    """Chunk CRCs, IHDR and the inflated scanline length of a 1-bit palette PNG."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "bad signature"
    offset, idat, width, height = 8, b"", 0, 0
    while offset < len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        kind = data[offset + 4:offset + 8]
        body = data[offset + 8:offset + 8 + length]
        crc = int.from_bytes(data[offset + 8 + length:offset + 12 + length], "big")
        if zlib.crc32(kind + body) != crc:
            return "bad crc " + kind.decode()
        if kind == b"IHDR":
            width, height = int.from_bytes(body[:4], "big"), int.from_bytes(body[4:8], "big")
            if body[8:] != b"\x01\x03\x00\x00\x00":
                return "unexpected IHDR"
        elif kind == b"IDAT":
            idat += body
        offset += 12 + length
    raw = zlib.decompress(idat)
    if len(raw) != height * ((width + 7) // 8 + 1):
        return "bad scanline length"
    return "ok %dx%d" % (width, height)


def page_checks(port, host, mode, headers, body, answer):
    page = Page()
    page.feed(body)
    csp = headers.get("content-security-policy", "")
    problems = []
    if "worker-src blob:" not in csp or "img-src 'self'" not in csp:
        problems.append("csp " + csp)
    if "data:image" in body or "<script nonce=" not in body or 'src="/.cdnca/challenge/solver.js?v=' not in body:
        problems.append("page script/picture not external")
    solver = re.search(r'src="(/\.cdnca/challenge/solver\.js\?v=[0-9a-f]+)"', body)
    if solver:
        status, solver_headers, script = request(port, host, "GET", solver.group(1))
        if status != 200 or "immutable" not in solver_headers.get("cache-control", "") or "function scan(" not in script:
            problems.append("solver.js %d %s" % (status, solver_headers.get("cache-control")))
    if "manual-continue" in body or "<noscript><button" in body:
        problems.append("no-JS submit button")
    if "需要启用 JavaScript" not in body:
        problems.append("missing noscript notice")
    visible = " ".join(page.text + page.labels)
    if mode == "captcha" and answer.upper() in body.upper():
        problems.append("captcha answer in page")
    if mode == "slider" and re.search(r"(?<![0-9])%s(?![0-9])" % re.escape(answer), visible):
        problems.append("slider target in page text")
    for url in re.findall(r'<img [^>]*src="(/\.cdnca/challenge/picture\?nonce=[A-Za-z0-9_-]+)"', body):
        status, picture_headers, data = request(port, host, "GET", url, raw=True)
        verdict = check_png(data) if status == 200 else "status %d" % status
        if not verdict.startswith("ok") or picture_headers.get("content-type") != "image/png":
            problems.append("png " + verdict)
        again = request(port, host, "GET", url, raw=True)[2]
        if again != data:
            problems.append("picture changes on reload")
        if request(port, host, "GET", url, user_agent="other-agent/1.0", raw=True)[0] != 403:
            problems.append("picture served to another user agent")
        if request(port, host, "GET", url[:-4] + "AAAA", raw=True)[0] != 403:
            problems.append("picture served for an unknown nonce")
    if mode in ("slider", "captcha") and "/.cdnca/challenge/picture?nonce=" not in body:
        problems.append("puzzle picture missing")
    return problems


def solve_case(port, admin_port, host, mode, case):
    started = time.monotonic()
    status, headers, body = request(port, host, "GET", "/solve?case=" + case)
    if status != 200:
        return {"case": case, "error": "challenge page status %d" % status}
    page = Page()
    page.feed(body)
    form = re.search(r'<form id="challenge-form"[^>]*>', body).group(0)
    attr = dict(re.findall(r'data-([a-z-]+)="([^"]*)"', form))
    nonce = re.search(r'name="nonce" value="([^"]+)"', body).group(1)
    with urllib.request.urlopen("http://127.0.0.1:%d/answer?nonce=%s" % (admin_port, nonce), timeout=5) as reply:
        answer = reply.read().decode().strip()
    problems = page_checks(port, host, mode, headers, body, answer)
    space = 2 ** int(attr["pow-difficulty"])
    pow_value = solve_pow(attr["pow-salt"], attr["pow-target"], int(attr["pow-difficulty"]))
    response = answer
    if case == "bad_pow":
        pow_value = (pow_value + 1) % space
    elif case == "bad_answer":
        response = str((int(answer) + 40) % 200) if mode == "slider" else "222222" if mode == "captcha" else "wrong"
    elif case == "tolerance_in":
        response = str(int(answer) + 3)
    elif case == "tolerance_out":
        response = str(int(answer) + 4)
    elif case in ("alt", "alt_early"):
        response = "wait"
    values = {"nonce": nonce, "response": response}
    if case != "no_pow":
        values["pow"] = str(pow_value)
    wait = {"alt": 5.3, "alt_early": 0.3, "early": 0.3}.get(case, 5.3 if mode == "delay" else 0.3)
    time.sleep(max(0, wait - (time.monotonic() - started)))
    status, headers, _ = request(port, host, "POST", "/.cdnca/challenge/verify", urllib.parse.urlencode(values))
    result = {"case": case, "status": status, "problems": problems}
    cookie = headers.get("set-cookie", "").split(";", 1)[0]
    if status == 303 and cookie:
        follow, _, origin = request(port, host, "GET", "/solve?case=" + case, cookie=cookie)
        result["origin"] = follow == 200 and "origin-ok" in origin
    return result


def solve(port, admin_port, spec):
    host, mode, cases = spec.split(":", 2)
    return host, [solve_case(port, admin_port, host, mode, case) for case in cases.split(",")]


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--pow":
        form = re.search(r'<form id="challenge-form"[^>]*>', open(sys.argv[2], encoding="utf-8").read()).group(0)
        attr = dict(re.findall(r'data-([a-z-]+)="([^"]*)"', form))
        print(solve_pow(attr["pow-salt"], attr["pow-target"], int(attr["pow-difficulty"])))
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "--solve":
        port, admin_port, specs = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4:]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(specs)) as pool:
            results = dict(pool.map(lambda spec: solve(port, admin_port, spec), specs))
        print(json.dumps(results, ensure_ascii=False, sort_keys=True))
        return 0
    if len(sys.argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    port = int(sys.argv[1])
    targets = [arg.split(":", 1) for arg in sys.argv[2:]]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as pool:
        results = list(pool.map(lambda target: scrape(port, target[0], target[1]), targets))
    print(json.dumps({r["host"]: r for r in results}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
