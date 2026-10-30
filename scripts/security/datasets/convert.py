#!/usr/bin/env python3
"""Turn the public WAF datasets into cdnca-waf-check -corpus-set std corpora.

Input (only the local cache, see README.md):  <cache>/raw/{legitimate.zip,
malicious.zip,eng_news_2023_100K.tar.gz} and the gotestwaf checkout.
Output: <cache>/corpus/<dataset>.jsonl.gz, one evalRequest per line:
  {"dataset","category","id","method","uri","headers","data","attack","fast"}

Replay follows each project's own client so the numbers are comparable:
  wafcomp   waf-comparison-project helper.send_request (python requests):
            URL requoted by requests, Host dropped, headers/body as recorded;
            "fast" marks the project's --fast subset (per file shuffle seed 42, 15%).
  gotestwaf payload x encoder x placeholder (internal/payload, Go client),
            config.yaml default headers; gRPC and GraphQL are skipped (a default
            run without -grpcPort / a GraphQL endpoint skips them too).
  leipzig   go-ftw quantitative: GET /get?uri_payload=<QueryEscape(sentence)>
            (category "query"), plus the same text as a form body (category "form").

usage: convert.py <cache dir>   (run with the cache venv: requests==2.32.3, PyYAML==6.0.2)
"""
import base64
import gzip
import hashlib
import json
import os
import random
import sys
import tarfile
import urllib.parse
import zipfile

import requests
import yaml

CACHE = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/.cache/cdnca-waf-datasets")
OUT = os.path.join(CACHE, "corpus")
DROP = {"host", "content-length", "connection", "transfer-encoding"}


def hexname(*parts):
    """GoTestWAF RandomHex(5): 10 hex chars; deterministic here."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:10]


def writer(name):
    os.makedirs(OUT, exist_ok=True)
    return gzip.open(os.path.join(OUT, name + ".jsonl.gz"), "wt", encoding="utf-8")


def emit(out, **request):
    out.write(json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n")


# ------------------------------------------------------------ waf-comparison

def fast_subset(data, seed=42, share=0.15):
    """waf-comparison-project Wafs._sample_data, byte for byte."""
    size = max(1, round(len(data) * share))
    copy = list(range(len(data)))
    random.seed(seed)
    random.shuffle(copy)
    return set(copy[:size])



# ------------------------------------------------------------ gotestwaf

def go_path_escape(value):
    """Go url.PathEscape (encodePathSegment: / ; , ? are escaped)."""
    return urllib.parse.quote(value, safe="$&+:=@-_.~")


def go_query_escape(value):
    """Go url.QueryEscape."""
    return urllib.parse.quote_plus(value, safe="-_.~")


def xml_escape(value):
    """Go xml.EscapeText as used by xml.Encoder.Encode(string)."""
    table = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&#34;", "'": "&#39;", "\t": "&#x9;", "\n": "&#xA;", "\r": "&#xD;"}
    return "".join(table.get(c, c) for c in value)


def encode(encoder, payload):
    if encoder == "Plain":
        return payload
    if encoder == "URL":
        return go_path_escape(payload)
    if encoder == "Base64":
        return base64.b64encode(payload.encode()).decode()
    if encoder == "Base64Flat":
        return base64.b64encode(payload.encode()).decode().replace("=", "")
    if encoder == "JSUnicode":
        units = payload.encode("utf-16-be")
        return "".join("\\u%02x%02x" % (units[i], units[i + 1]) for i in range(0, len(units), 2))
    if encoder == "XMLEntity":
        return "<string>" + xml_escape(payload) + "</string>"
    raise ValueError(encoder)


def has_ctl(value):
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)


def go_target(target):
    """The request target Go's client sends for http://waf.test + target, or None
    when http.NewRequest fails (GoTestWAF counts that as failed, not sent)."""
    if has_ctl(target):
        return None
    target = target.split("#", 1)[0]
    path, sep, query = target.partition("?")
    try:
        unquoted = urllib.parse.unquote(path, errors="strict")
    except UnicodeDecodeError:
        unquoted = None
    for index, char in enumerate(path):  # url.Parse rejects bad escapes in the path
        if char == "%" and not all(c in "0123456789abcdefABCDEF" for c in path[index + 1:index + 3]) or \
                (char == "%" and len(path[index + 1:index + 3]) < 2):
            return None
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@/%")
    if not all(c in allowed for c in path):
        source = unquoted if unquoted is not None else urllib.parse.unquote(path)
        path = urllib.parse.quote(source, safe="$&+,/:;=@-_.~")
    return path + sep + query


SEED_BOUNDARY = "5f0c3e2a9b7d4e1f8a6c0b3d2e9f7a1c4b8d6e0f2a3c5b7d9e1f0a2c4e6b"


def placeholder_request(name, config, encoded, key):
    """One GoTestWAF placeholder; returns (method, target, headers, body) or None."""
    hexkey = hexname(key)
    json_type = {"Content-Type": "application/json"}
    if name == "URLParam":
        target = go_target("/?" + hexkey + "=" + encoded)
        return target and ("GET", target, {}, "")
    if name == "URLPath":
        target = go_target("/" + encoded)
        return target and ("GET", target, {}, "")
    if name == "Header":
        return None if has_ctl(encoded) else ("GET", "/", {"X-" + hexkey: encoded}, "")
    if name == "UserAgent":
        return None if has_ctl(encoded) else ("GET", "/", {"User-Agent": encoded}, "")
    if name == "JSONRequest":
        return ("POST", "/", json_type, '{"test": true, "%s": "%s"}' % (hexkey, encode("JSUnicode", encoded)))
    if name == "JSONBody":
        return ("POST", "/", json_type, encoded)
    if name == "HTMLForm":
        return ("POST", "/", {"Content-Type": "application/x-www-form-urlencoded"}, hexkey + "=" + encoded)
    if name == "HTMLMultipartForm":
        body = ("--" + SEED_BOUNDARY + "\r\nContent-Disposition: form-data; name=\"" + hexkey + "\"\r\n\r\n" +
                encoded + "\r\n--" + SEED_BOUNDARY + "--\r\n")
        return ("POST", "/", {"Content-Type": "multipart/form-data; boundary=" + SEED_BOUNDARY}, body)
    if name == "XMLBody":
        return ("POST", "/", {"Content-Type": "application/xml"}, encoded)
    if name == "SOAPBody":
        tag = "ab" + hexkey
        body = SOAP % (tag, encode("XMLEntity", encoded), tag)
        return ("POST", "/", {"Content-Type": "text/xml", "SOAPAction": '"http://schemas.xmlsoap.org/soap/actor/next"'}, body)
    if name == "RawRequest":
        path = config.get("path", "/")
        target = go_target("/" + path.lstrip("/").replace("{{payload}}", go_path_escape(encoded)))
        headers = {k: str(v).replace("{{payload}}", encoded) for k, v in (config.get("headers") or {}).items()}
        if target is None or any(has_ctl(v) for v in headers.values()):
            return None
        return (config.get("method", "GET"), target, headers, str(config.get("body") or "").replace("{{payload}}", encoded))
    return None  # GraphQL / gRPC: need -graphqlURL / -grpcPort, a default run skips them


SOAP = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
	xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<soapenv:Header>
		<ns1:RequestHeader soapenv:actor="http://schemas.xmlsoap.org/soap/actor/next"
			soapenv:mustUnderstand="0" xmlns:ns1="https://www.google.com/apis/ads/publisher/v202002">
		</ns1:RequestHeader>
	</soapenv:Header>
	<soapenv:Body>
		<getAdUnitsByStatement xmlns="https://www.google.com/apis/ads/publisher/v202002">
			<filterStatement>
				<%s>%s</%s>
			</filterStatement>
		</getAdUnitsByStatement>
	</soapenv:Body>
</soapenv:Envelope>"""


def gotestwaf():
    root = os.path.join(CACHE, "gotestwaf")
    defaults = yaml.safe_load(open(os.path.join(root, "config.yaml")))["headers"]
    defaults = {k: str(v) for k, v in defaults.items() if k.lower() not in DROP}
    counts = {"total": 0, "skipped": 0}
    with writer("gotestwaf") as out:
        # raw/gotestwaf-cases.json: the test cases as GoTestWAF's yaml.v2 parses them
        # (gotestwaf-dump.go.txt; PyYAML rejects escapes such as \' that yaml.v2 accepts)
        for case in json.load(open(os.path.join(CACHE, "raw", "gotestwaf-cases.json"))):
            test_set, case_name = case["set"], case["case"]
            if True:
                for p_index, payload in enumerate(case["payload"]):
                    for encoder in case["encoder"]:
                        for placeholder in case["placeholder"]:
                            name, config = (placeholder, {}) if isinstance(placeholder, str) else next(iter(placeholder.items()))
                            counts["total"] += 1
                            key = f"{test_set}/{case_name}-{p_index}-{encoder}-{name}"
                            built = placeholder_request(name, config or {}, encode(encoder, str(payload)), key)
                            if built is None:
                                counts["skipped"] += 1
                                continue
                            method, target, headers, body = built
                            merged = dict(headers)
                            lower = {k.lower() for k in merged}
                            for k, v in defaults.items():
                                if k.lower() == "user-agent" and name == "UserAgent":
                                    continue
                                if k.lower() not in lower:
                                    merged[k] = v
                            emit(out, dataset="gotestwaf", category=f"{test_set}/{case_name}:{name}:{encoder}", id=key,
                                 method=method, uri=target, headers=merged, data=body, attack=test_set != "false-pos")
    return counts


# ------------------------------------------------------------ leipzig

FTW_HEADERS = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75. 0.3770.100 Safari/537.36",
               "Accept": "*/*"}


def leipzig():
    counts = {"total": 0, "skipped": 0}
    member = "eng_news_2023_100K/eng_news_2023_100K-sentences.txt"
    with tarfile.open(os.path.join(CACHE, "raw", "eng_news_2023_100K.tar.gz")) as archive, writer("leipzig") as out:
        for line in archive.extractfile(member).read().decode("utf-8").splitlines():
            split = line.split("\t")
            number, text = split[0], " ".join(split[1:])
            counts["total"] += 1
            value = go_query_escape(text)
            emit(out, dataset="leipzig", category="query", id=f"q{number}", method="GET", uri="/get?uri_payload=" + value,
                 headers=FTW_HEADERS, data="", attack=False)
            emit(out, dataset="leipzig", category="form", id=f"f{number}", method="POST", uri="/get",
                 headers=dict(FTW_HEADERS, **{"Content-Type": "application/x-www-form-urlencoded"}),
                 data="uri_payload=" + value, attack=False)
    return counts


# ------------------------------------------------------------ waf-comparison: python requests replay

REQUESTS_DEFAULTS = {"User-Agent": "python-requests/2.32.3", "Accept-Encoding": "gzip, deflate", "Accept": "*/*"}


def wafcomp_request(request):
    """(target, headers, body) as python requests sends it, or None when it raises
    (the project then records status 0 and leaves the request out)."""
    headers = {k: v for k, v in (request.get("headers") or {}).items() if k.lower() != "host"}
    data = request.get("data") or ""
    try:
        prepared = requests.Request(request["method"], "http://waf.test" + request["url"], headers=headers,
                                    data=data or None).prepare()
        target = prepared.path_url
        body = prepared.body or ""
        if isinstance(body, bytes):
            body = body.decode("latin-1")
        body.encode("latin-1")  # http.client encodes str bodies as ISO-8859-1
        merged = dict(REQUESTS_DEFAULTS)
        lower = {k.lower(): k for k in merged}
        for k, v in prepared.headers.items():
            str(v).encode("latin-1")
            if has_ctl(str(v)) and "\t" not in str(v):
                return None
            merged.pop(lower.get(k.lower(), k), None)
            merged[k] = str(v)
    except Exception:
        return None
    return target, {k: v for k, v in merged.items() if k.lower() not in DROP}, body


def wafcomp_set(zip_name, dataset, attack):
    counts = {"total": 0, "skipped": 0}
    with zipfile.ZipFile(os.path.join(CACHE, "raw", zip_name)) as archive, writer(dataset) as out:
        for member in sorted(n for n in archive.namelist() if n.endswith(".json")):
            data = json.loads(archive.read(member))
            fast = fast_subset(data)
            stem = os.path.splitext(os.path.basename(member))[0]
            for index, request in enumerate(data):
                counts["total"] += 1
                built = wafcomp_request(request)
                if built is None:
                    counts["skipped"] += 1
                    continue
                target, headers, body = built
                emit(out, dataset=dataset, category=stem, id=f"{stem}-{index}", method=request["method"], uri=target,
                     headers=headers, data=body, latin1=True, attack=attack, fast=index in fast)
    return counts


if __name__ == "__main__":
    only = set(sys.argv[2].split(",")) if len(sys.argv) > 2 else {"gotestwaf", "leipzig", "wafcomp-mal", "wafcomp-legit"}
    summary = {}
    if "gotestwaf" in only:
        summary["gotestwaf"] = gotestwaf()
    if "leipzig" in only:
        summary["leipzig"] = leipzig()
    if "wafcomp-mal" in only:
        summary["wafcomp-mal"] = wafcomp_set("malicious.zip", "wafcomp-mal", True)
    if "wafcomp-legit" in only:
        summary["wafcomp-legit"] = wafcomp_set("legitimate.zip", "wafcomp-legit", False)
    print(json.dumps(summary))