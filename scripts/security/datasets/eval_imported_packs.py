#!/usr/bin/env python3
"""官方规则包评测：真实 OpenResty（libs/rulepack 匹配索引测试同一镜像与解释器 harness）跑全部官方 waf_v2 包的规则计划，
按包统计命中，再与已有四档 CRS 结果合并，得出“包动作改为 block 后”各档拦截率/误报率的变化。

用法：python3 eval_imported_packs.py <out-dir>
输入：
  RULEPACK_PLAN_OUT 产物（本脚本先跑 rulepackcheck.sh 生成：0.json 计划 + rules.json 节点规则 → 包）
  seed 攻击：~/.cache/cdnca-waf-datasets/corpus/eval-seed/eval-lines.jsonl.gz（含四档 tiers）
  waf-comparison fast：corpus/wafcomp-{legit,mal}.jsonl.gz 中 fast=true 的请求；四档结果取 runs/fast/*.log 的 STDHIT 行
输出：<out-dir>/hits.jsonl.gz（每请求命中的包）、summary.md、summary.json
"""
import base64
import collections
import glob
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../.."))
DATA = os.path.expanduser("~/.cache/cdnca-waf-datasets")
IMAGE = "openresty/openresty@sha256:035818c9596ce60cdc816fc1941db0414d50398644ec9567b45fded04a76e7d0"
TIERS = ["仅记录", "标准防护", "严格防护", "极严格防护"]
PORT = 18080
HOP = {"host", "content-length", "connection", "transfer-encoding", "keep-alive", "expect", "x-cdnca-case", "x-cdnca-time"}

CONF = """worker_processes 2;
error_log logs/error.log warn;
pid logs/nginx.pid;
events { worker_connections 1024; }
http {
  access_log off;
  lua_package_path "$prefix/lua/?.lua;;";
  client_body_temp_path /tmp/rule-index-body;
  client_body_buffer_size 128k;
  client_max_body_size 16m;
  large_client_header_buffers 8 64k;
  lua_shared_dict cdnca_waf_state 4m;
  init_by_lua_block { require("index_harness").preload(1) }
  server {
    listen 127.0.0.1:%d;
    server_name _;
    set $cdnca_security_emit 0;
    set $cdnca_security_type "";
    set $cdnca_security_action "";
    set $cdnca_security_severity "";
    set $cdnca_security_rule_id "";
    set $cdnca_block_page 0;
    set $cdnca_security_policy_id "";
    set $cdnca_security_detector "";
    set $cdnca_security_matched "";
    set $cdnca_security_body "";
    set $cdnca_ja4 "";
    location / { content_by_lua_block { require("index_harness").content() } }
  }
}
""" % PORT


def raw_request(method, uri, headers, data, latin1=False):
    body = (data or "").encode("latin-1" if latin1 else "utf-8", "replace")
    lines = ["%s %s HTTP/1.1" % (method or "GET", uri or "/"), "Host: eval.test", "X-Cdnca-Case: index:0", "Connection: close"]
    for name, value in (headers or {}).items():
        if name.lower() not in HOP and "\r" not in str(value) and "\n" not in str(value):
            lines.append("%s: %s" % (name, value))
    if body or (method or "GET") in ("POST", "PUT", "PATCH"):
        lines.append("Content-Length: %d" % len(body))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "replace") + body


def corpus():
    """(set, id, attack, tiers[4] or None, raw)"""
    with gzip.open(os.path.join(DATA, "corpus/eval-seed/eval-lines.jsonl.gz"), "rt") as f:
        for line in f:
            d = json.loads(line[5:])
            yield "seed/attack", d["id"], True, d["tiers"], raw_request(d["method"], d["uri"], d.get("headers"), d.get("data"))
    for name, attack in (("wafcomp-legit", False), ("wafcomp-mal", True)):
        with gzip.open(os.path.join(DATA, "corpus/%s.jsonl.gz" % name), "rt") as f:
            for line in f:
                d = json.loads(line)
                if d.get("fast"):
                    yield "%s/%s" % (name, "attack" if attack else "benign"), d["id"], attack, None, \
                        raw_request(d["method"], d["uri"], d.get("headers"), d.get("data"), d.get("latin1"))


def fast_tiers():
    """id -> set of CRS tiers (1..3) that blocked it, from the fast run's STDHIT lines; excluded ids."""
    hits, excluded = {}, set()
    for path in glob.glob(os.path.join(DATA, "runs/fast/wafcomp-*.log")):
        for line in open(path, errors="replace"):
            parts = line.split()
            if line.startswith("STDHIT "):
                tiers = parts[3].split("=", 1)[1]
                hits[parts[2]] = {int(c) for c in tiers}
            elif line.startswith("STDEXC "):
                excluded.add(parts[2])
    return hits, excluded


def run_container(work, requests):
    name = "cdnca-rule-gpl-import-eval-%d" % os.getpid()
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "--network", "none", "-v", work + ":/w",
                    "--entrypoint", "sh", IMAGE, "-c", "sleep 7200"], check=True, capture_output=True)
    try:
        subprocess.run(["docker", "exec", name, "sh", "-c", "openresty -p /w/ -c nginx.conf"], check=True, capture_output=True)
        results = {}
        batch = []

        def flush():
            stdin = "".join(json.dumps({"id": rid, "port": PORT, "raw": base64.b64encode(raw).decode()}) + "\n" for rid, raw in batch)
            out = subprocess.run(["docker", "exec", "-i", name, "sh", "-c",
                                  "cat > /tmp/r.jsonl && cd /w && resty lua/rule_client.lua /tmp/r.jsonl /tmp/o.jsonl 16 >/dev/null && cat /tmp/o.jsonl"],
                                 input=stdin.encode(), capture_output=True, check=True)
            for line in out.stdout.decode().splitlines():
                d = json.loads(line)
                results[d["id"]] = (d["status"], d["result"])
            batch.clear()
        for rid, raw in requests:
            batch.append((rid, raw))
            if len(batch) >= 20000:
                flush()
                print("sent", len(results), flush=True)
        if batch:
            flush()
        return results
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    work = tempfile.mkdtemp(prefix="rgi-eval-")
    try:
        for d in ("lua", "plans", "logs"):
            os.makedirs(os.path.join(work, d))
        env = dict(os.environ, RULEPACK_PLAN_OUT=os.path.join(work, "plans"))
        subprocess.run(["sh", os.path.join(HERE, "rulepackcheck.sh")], env=env, check=True, capture_output=True)
        rules = json.load(open(os.path.join(work, "plans/rules.json")))
        for source in ("edge/openresty/lua/cdnca_rule_interp.lua", "edge/openresty/lua/cdnca_waf.lua"):
            shutil.copy(os.path.join(REPO, source), os.path.join(work, "lua"))
        for name in ("index_harness.lua", "cdnca_iplib.lua", "rule_client.lua"):
            shutil.copy(os.path.join(REPO, "libs/rulepack/testdata/ruleindex", name), os.path.join(work, "lua"))
        open(os.path.join(work, "nginx.conf"), "w").write(CONF)
        subprocess.run(["chmod", "-R", "a+rwX", work], check=True)
        meta = {}
        items = []
        limit, seen = int(os.environ.get("EVAL_LIMIT", "0")), collections.Counter()
        for set_name, rid, attack, tiers, raw in corpus():
            seen[set_name] += 1
            if limit and seen[set_name] > limit:
                continue
            key = set_name + "\t" + rid
            meta[key] = (set_name, attack, tiers)
            items.append((key, raw))
        results = run_container(work, items)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    crs, excluded = fast_tiers()
    imported = {os.path.basename(p)[len("system-"):-5] for p in glob.glob(os.path.join(HERE, "rulepacks/imported/system-*.json"))}
    totals = collections.Counter()
    packs = collections.Counter()
    blocked = collections.Counter()  # (set, tier, variant)
    with gzip.open(os.path.join(out, "hits.jsonl.gz"), "wt") as hits_file:
        for key, (status, result) in results.items():
            set_name, attack, tiers = meta[key]
            rid = key.split("\t", 1)[1]
            if status != 200 or (tiers is None and rid in excluded):
                totals[(set_name, "excluded")] += 1
                continue
            trace = result.split("|")[4] if result.count("|") >= 4 else ""
            hit = set()
            for item in trace.split(","):
                parts = item.split(":", 2)
                if len(parts) == 3 and parts[1] == "log" and parts[2] in rules:
                    hit.add(rules[parts[2]][0].split("/", 1)[1])
            new = hit & imported
            totals[(set_name, "counted")] += 1
            for name in hit:
                packs[(set_name, name)] += 1
            if hit:
                hits_file.write(json.dumps({"set": set_name, "id": rid, "packs": sorted(hit)}) + "\n")
            crs_tiers = {i for i, v in enumerate(tiers) if v} if tiers is not None else crs.get(rid, set())
            for tier in range(4):
                base = tier in crs_tiers
                blocked[(set_name, tier, "crs")] += base
                blocked[(set_name, tier, "crs+old7")] += base or bool(hit - imported)
                blocked[(set_name, tier, "crs+all14")] += base or bool(hit)
            totals[(set_name, "new_only")] += bool(new) and not (hit - imported)
    sets = sorted({s for s, _ in totals})
    summary = {"totals": {"%s/%s" % k: v for k, v in totals.items()}, "packs": {"%s/%s" % k: v for k, v in packs.items()},
               "blocked": {"%s/%d/%s" % k: v for k, v in blocked.items()}}
    json.dump(summary, open(os.path.join(out, "summary.json"), "w"), ensure_ascii=False, indent=1)
    lines = ["## 四档拦截/误报（包动作改为 block 后；CRS 档结果取已有评测）", "",
             "| 集 | 样本 | 档 | 仅 CRS | +已发布 7 包 | +全部 14 包（7 旧 + 7 新） |", "|---|---|---|---|---|---|"]
    for s in sets:
        n = totals[(s, "counted")]
        for tier in range(4):
            cells = ["%.2f%%" % (100.0 * blocked[(s, tier, v)] / max(n, 1)) for v in ("crs", "crs+old7", "crs+all14")]
            lines.append("| %s | %d | %s | %s |" % (s, n, TIERS[tier], " | ".join(cells)))
    lines += ["", "## 按包命中（默认 log 时的记录数）", "", "| 包 | " + " | ".join(sets) + " |", "|---|" + "---|" * len(sets)]
    for name in sorted({p for _, p in packs}):
        row = ["%d (%.2f%%)" % (packs[(s, name)], 100.0 * packs[(s, name)] / max(totals[(s, "counted")], 1)) for s in sets]
        lines.append("| %s%s | %s |" % (name, "（新）" if name in imported else "", " | ".join(row)))
    lines += ["", "排除（状态非 200 或原评测排除）：" + "，".join("%s %d" % (s, totals[(s, "excluded")]) for s in sets)]
    open(os.path.join(out, "summary.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
