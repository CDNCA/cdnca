#!/usr/bin/env python3
"""seed-attacks.jsonl.gz → cdnca-waf-check 攻击语料（分层抽样 ≤N 条，五个位置轮换）。

用法：build_eval_corpus.py [-n 5000] [-batch 1000] [-real] <out-dir>
输出：<out-dir>/batch-XX.json（evalRequest 数组，字段同 waf-strict-algo 的 cdnca-waf-check corpus.go）。

- 抽样：按类别等额分配，小类全取，余额再均分给大类（注水法）；固定随机种子，结果确定。
- 位置：每类内按序轮换 query / form / json / cookie / header。
- 类别与位置写进 ID（seed-<类别>-<位置>-<序号>）：工具读 -corpus 时会用 Rule 改写 Category，
  这里 Rule 固定填 100（工具取 Itoa(Rule)[:3]，不能为 0），汇总只看 ID。
"""
import argparse
import gzip
import json
import os
import random
import urllib.parse

SRC = os.path.expanduser("~/.cache/cdnca-waf-datasets/corpus/seed-attacks.jsonl.gz")
LOCS = ["query", "form", "json", "cookie", "header"]
MAX_VALUE = 3000  # 头部/Cookie 不超 nginx 默认 large_client_header_buffers 8k


def header_safe(value, extra=""):
    """头部与 Cookie 不能带 CR/LF/控制字符：这些字节与 extra 中的字符按 %XX 编码，其余原样。"""
    out = []
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) == 0x7F or ch in extra:
            out.append("%%%02X" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


# waf-gap4：SecLists 的 LDAP 属性名、上传扩展名字典单独作参数值不是攻击（rule-seed §3）。
# ldap：攻击形态 = 把属性名套进过滤器注入模板（闭合应用过滤器再开新项）；种子里本身含括号的照原样。
# upload：攻击形态 = multipart/form-data 上传，文件名为 webshell 或双扩展名、内容为一句话木马；
#   位置轮换改为文件名写法轮换（直接扩展名 / 双扩展名 / 截断 / 大小写），id 里位置记 upload。
LDAP_TEMPLATES = ["*)({a}=*))(|({a}=*", "admin)(&({a}=*))", "*)(|({a}=*))", "(|({a}=*)(cn=*))", "admin*)((|{a}=*)"]
UPLOAD_NAMES = ["shell.{e}", "avatar.jpg.{e}", "shell.{e}.jpg", "shell.{e}%00.jpg", "Shell.{E}"]
UPLOAD_BODY = "<?php @eval($_POST['c']); ?>"
# 服务端可执行扩展名（Apache/IIS/Tomcat 常见映射，与节点 upload 检测器无关地独立列出）
EXEC = set("php php3 php4 php5 php7 pht phtml phar asp aspx asa cer ashx jsp jspx cgi pl py shtml".split())
EXEC_ROTATE = ["php", "phtml", "php5", "aspx", "asp", "jsp", "jspx", "phar", "cer", "shtml"]


def real_attack(cat, payload, i):
    """返回 (payload, loc 覆盖)：ldap 套模板；upload 返回整个 multipart 请求。"""
    if cat == "ldap" and not any(c in payload for c in "()*|&"):
        attr = payload.strip() or "uid"
        return LDAP_TEMPLATES[i % len(LDAP_TEMPLATES)].format(a=attr), None
    if cat == "upload":
        # 字典里的扩展名多为普通文件类型（.saf .mp3），只有服务端可执行的才构成攻击；其余换成 EXEC 轮换
        ext = payload.strip().lstrip(".").split(".")[-1].lower()
        if ext not in EXEC:
            ext = EXEC_ROTATE[i % len(EXEC_ROTATE)]
        return UPLOAD_NAMES[i % len(UPLOAD_NAMES)].format(e=ext, E=ext.upper()), "upload"
    return payload, None


def multipart(rid, filename):
    boundary = "----cdnca" + rid.replace("-", "")[-16:]
    body = ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n%s\r\n--%s--\r\n") % (boundary, filename, UPLOAD_BODY, boundary)
    return {"id": rid, "category": "seed", "rule": 100, "attack": True, "method": "POST", "uri": "/t", "data": body,
            "headers": {"Content-Type": "multipart/form-data; boundary=" + boundary}}


def to_request(rid, payload, loc):
    q = urllib.parse.quote(payload, safe="")
    r = {"id": rid, "category": "seed", "rule": 100, "attack": True}
    if loc == "query":
        r.update(method="GET", uri="/t?v=" + q)
    elif loc == "form":
        r.update(method="POST", uri="/t", data="v=" + q, headers={"Content-Type": "application/x-www-form-urlencoded"})
    elif loc == "json":
        r.update(method="POST", uri="/t", data=json.dumps({"v": payload}, ensure_ascii=False), headers={"Content-Type": "application/json"})
    elif loc == "cookie":
        r.update(method="GET", uri="/t", headers={"Cookie": "v=" + header_safe(payload, ";")})
    else:
        r.update(method="GET", uri="/t", headers={"X-Data": header_safe(payload)})
    return r


def allocate(sizes, total):
    quota, left, open_ = {}, total, dict(sizes)
    while open_:
        share = left // len(open_)
        small = {k: v for k, v in open_.items() if v <= share}
        if not small:
            for i, k in enumerate(sorted(open_)):
                quota[k] = share + (1 if i < left - share * len(open_) else 0)
            break
        for k, v in small.items():
            quota[k] = v
            left -= v
            del open_[k]
    return quota


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=5000)
    ap.add_argument("-batch", type=int, default=1000)
    ap.add_argument("-real", action="store_true", help="ldap/upload 改为真实攻击形态（waf-gap4）")
    ap.add_argument("out")
    a = ap.parse_args()
    by = {}
    with gzip.open(SRC, "rt") as f:
        for line in f:
            r = json.loads(line)
            p = r["payload"]
            if p.strip() and len(p) <= MAX_VALUE:
                by.setdefault(r["category"], []).append(p)
    quota = allocate({k: len(v) for k, v in by.items()}, a.n)
    rng = random.Random(20261020)
    corpus = []
    for cat in sorted(by):
        items = sorted(by[cat])
        pick = items if quota[cat] >= len(items) else rng.sample(items, quota[cat])
        for i, p in enumerate(pick):
            loc = LOCS[i % len(LOCS)]
            if a.real:
                p, override = real_attack(cat, p, i)
                if override == "upload":
                    corpus.append(multipart(f"seed-{cat}-upload-{i}", p))
                    continue
            corpus.append(to_request(f"seed-{cat}-{loc}-{i}", p, loc))
    rng.shuffle(corpus)  # 批次之间类别分布一致
    os.makedirs(a.out, exist_ok=True)
    for b in range(0, len(corpus), a.batch):
        with open(os.path.join(a.out, "batch-%02d.json" % (b // a.batch)), "w") as f:
            json.dump(corpus[b:b + a.batch], f, ensure_ascii=False)
    print(len(corpus), {k: min(quota[k], len(by[k])) for k in sorted(by)})


if __name__ == "__main__":
    main()