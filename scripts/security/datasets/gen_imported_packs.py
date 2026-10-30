#!/usr/bin/env python3
"""非宽松许可证来源的规则原文 → 官方系统层规则包（直接转换原文，不注明出处）。

用法：~/.cache/cdnca-waf-datasets/venv/bin/python gen_imported_packs.py [<out-dir>，默认 rulepacks/imported]
（device-detector 是 YAML，需要 venv 里的 PyYAML）
输入：~/.cache/cdnca-waf-datasets/seed/src 下 wargio/naxsi、matomo-org/device-detector、bunkerity/bunkerweb
（提交号见 SOURCES.md）；去重参照 rulepacks/ 下已发布的 7 个官方包；误伤过滤用 wafcomp-legit 的真实 UA。
输出（都是 waf_v2、版本 1.0.0、默认动作 log，参数 action 可改 block/challenge）：
  system-naxsi-strong.json    naxsi_core.rules 中多字符强特征（naxsi-core 是白名单式计分，单字符特征
                              逐个加分，原样转换正常集命中 71.7%，不发布；只保留 waf-comparison fast 正常集单规则命中 <0.5% 的
                              多字符特征，筛选见 screen_naxsi_strong.py → rulepacks/imported/naxsi-strong-screen.json）
  system-naxsi-scanner.json   blocking/10000000_scanner.rules：扫描器 UA/特征
  system-naxsi-websec.json    blocking/20000000 web_security + 30000000 wordpress + 40000000 php
  system-naxsi-sqli.json      blocking/50000000_sql_injection.rules
  system-bot-dd-scraper.json  device-detector bots.yml：采集/AI/安全扫描类
  system-bot-dd-service.json  device-detector bots.yml：搜索/监控/服务/预览类（已剔除已知良性爬虫）
  system-bw-request-limits.json bunkerweb misc 默认值：非允许方法、请求头数、请求体大小
发布：生成后同时复制到 services/license-service/internal/licensing/officialpacks/（嵌入二进制，授权端每次启动
  PublishOfficialRulePacks 把尚无任何版本的包发布为 revision 1；契约测试断言两处逐字节一致）。
  import-stats.json           转换统计（丢弃项与原因）
  trusted-crawler-uas.json    已知良性爬虫 UA 样本（arcjet well-known-bots instances，MIT），rulepackcheck 回归：
                              新包任何 UA 规则都不得命中

naxsi 打分语义（CheckRule $SQL/$RFI/$XSS/$EVADE >= 8，$TRAVERSAL/$UPLOAD >= 5，每次命中按次数累加）
在 waf_v2 里没有分数累加，按下面规则转换：
  * 单条分数已达阈值的特征：任一出现即命中（contains / regex）；
  * 两次命中才达阈值的特征（如 SQL 关键字 4 分）：同一个值里出现两次（同一特征或两个不同特征）即命中
    （regex `(?:A|B..)[\\s\\S]*(?:A|B..)`）；跨不同参数凑分不转换；
  * 需要 3 次以上才达阈值的（2 分特征）不转换；节点会反复 URL 解码，二次编码特征（%[23].）看不到，不转换。
  * 区域：ARGS/BODY → args（含查询串与表单/JSON 值），URL → request_uri（core，不被 nginx 规范化吃掉 ..）
    或 path（blocking 的路径特征），$HEADERS_VAR:Cookie → cookie，$HEADERS_VAR:User-Agent → user_agent，
    HEADERS → user_agent/referer/cookie，ANY → args/request_uri/user_agent/referer/cookie，RAW_BODY → body，
    FILE_EXT → upload_filename，$URL:<p>|... → 路径精确等于 p 且后续区域命中；naxsi 正则都是不区分大小写（CASELESS）。
"""
import glob
import gzip
import json
import os
import re
import re._parser as sre_parse
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.expanduser("~/.cache/cdnca-waf-datasets/seed/src")
LEGIT = os.path.expanduser("~/.cache/cdnca-waf-datasets/corpus/wafcomp-legit.jsonl.gz")
UA_CACHE = os.path.expanduser("~/.cache/cdnca-waf-datasets/corpus/wafcomp-legit-uas.json")
MAX_VALUES = 64
MAX_REGEX = 500  # libs/rulepack maxRegexBytes 512
MAX_UNBOUNDED = 4
VERSION = "1.0.0"
ACTION = {"type": "string", "enum": ["log", "block", "challenge"], "bind": {"target": "waf.action", "rules": []}}
THRESHOLD = {"SQL": 8, "RFI": 8, "XSS": 8, "EVADE": 8, "TRAVERSAL": 5, "UPLOAD": 5, "UWA": 8}
CAT_NAME = {"SQL": "SQL 注入", "RFI": "远程文件包含", "XSS": "XSS", "EVADE": "编码绕过", "TRAVERSAL": "目录穿越", "UPLOAD": "危险上传"}
TARGET_NAME = {"args": "参数", "request_uri": "URL", "cookie": "Cookie", "path": "路径", "user_agent": "UA", "referer": "Referer",
               "body": "请求体", "query": "查询参数", "upload_filename": "上传文件名", "header": "请求头"}
CORE_ZONE = {"ARGS": ["args"], "BODY": ["args"], "URL": ["request_uri"], "$HEADERS_VAR:Cookie": ["cookie"], "FILE_EXT": ["upload_filename"]}
BLOCK_ZONE = {"ARGS": ["args"], "BODY": ["args"], "URL": ["path"], "$HEADERS_VAR:Cookie": ["cookie"],
              "$HEADERS_VAR:User-Agent": ["user_agent"], "HEADERS": ["user_agent", "referer", "cookie"],
              "ANY": ["args", "request_uri", "user_agent", "referer", "cookie"], "RAW_BODY": ["body"],
              "FILE_EXT": ["upload_filename"], "$HEADERS_VAR:Accept": [("header", "accept")],
              "$HEADERS_VAR:Content-length": [("header", "content-length")]}
stats = {"dropped": [], "rewritten": []}
# naxsi regexes over the node budget (libs/rulepack checkRegex: at most 4 unbounded repeats), rewritten to an
# equivalent-or-wider pattern: id -> (original, rewritten).
NAXSI_REWRITE = {20000038: (r"<!DOCTYPE(\s+)(%*\s*)([{}:.a-zA-Z0-9_-]*)(\s+)SYSTEM",
                            r"<!DOCTYPE\s+[%\s]*[{}:.a-zA-Z0-9_-]*\s+SYSTEM")}


def src(prefix):
    return glob.glob(os.path.join(SRC, prefix + "-*"))[0]


def drop(source, item, reason):
    stats["dropped"].append({"source": source, "item": item, "reason": reason})


# ---------------------------------------------------------------- regex helpers
def regex_shape(pattern):
    """(unbounded repeats, ok) under libs/rulepack checkRegex: no nested repetition, counted repeats <= 256."""
    try:
        parsed = sre_parse.parse(pattern)
    except re.error:
        return 0, False
    unbounded, ok = 0, True

    def walk(items, depth):
        nonlocal unbounded, ok
        for op, av in items:
            name = str(op)
            if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                low, high, sub = av
                if high == sre_parse.MAXREPEAT:
                    unbounded += 1
                elif high > 256 or low > 256:
                    ok = False
                repeated = high == sre_parse.MAXREPEAT or high > 1
                if repeated and depth >= 1:
                    ok = False
                walk(sub, depth + (1 if repeated else 0))
            elif name in ("ASSERT", "ASSERT_NOT", "GROUPREF", "GROUPREF_EXISTS", "ATOMIC_GROUP"):
                ok = False
            elif name == "SUBPATTERN":
                walk(av[-1], depth)
            elif name == "BRANCH":
                for sub in av[1]:
                    walk(sub, depth)
    walk(parsed, 0)
    return unbounded, ok


def alt_literals(pattern):
    """'a|b\\.c' → ['a', 'b.c'] when every branch is a plain literal, else None."""
    out = []
    for part in pattern.split("|"):
        text = re.sub(r"\\([^A-Za-z0-9])", r"\1", part)
        if not part or re.search(r"\\[A-Za-z0-9]", part) or re.search(r"[\^$\[\]()*+?{}.]", re.sub(r"\\.", "", part)):
            return None
        out.append(text)
    return out


def regex_chunks(patterns, prefix="(?i)", wrap=("(?:", ")")):
    """Merge patterns into alternations within the regex size / unbounded-repeat budget."""
    chunks, current, current_unbounded = [], [], 0
    for pattern in patterns:
        unbounded, _ = regex_shape(pattern)
        candidate = prefix + wrap[0] + "|".join(current + [pattern]) + wrap[1]
        if current and (len(candidate) > MAX_REGEX or current_unbounded + unbounded > MAX_UNBOUNDED):
            chunks.append(prefix + wrap[0] + "|".join(current) + wrap[1])
            current, current_unbounded = [], 0
        current.append(pattern)
        current_unbounded += unbounded
    if current:
        chunks.append(prefix + wrap[0] + "|".join(current) + wrap[1])
    return chunks


def printable(value):
    return 0 < len(value) <= 1024 and "\r" not in value and "\n" not in value and "\x00" not in value


def chunks(values, size=MAX_VALUES):
    values = sorted(set(values))
    return [values[i:i + size] for i in range(0, len(values), size)]


# ---------------------------------------------------------------- pack helpers
def rule(rid, name, inspect, method=None, path=None):
    match = {}
    if method:
        match["method"] = method
    if path:
        match["path"] = path
    if inspect:
        match["inspect"] = inspect
    return {"id": rid, "name": name, "waf": {"match": match, "action": "log", "flow": "continue"}}


def clause(target, operator, values, key=None):
    item = {"target": target, "operator": operator, "values": values}
    if key:
        item["key"] = key
    return item


def pack(name, title, description, rules):
    if len(rules) > 256:
        raise SystemExit("%s: %d rules over 256" % (name, len(rules)))
    return {"schema": "cdnca.rule-pack/v1", "pack_id": "system/" + name, "version": VERSION, "layer": "system",
            "engine": "waf_v2", "engine_min_version": 1, "name": title, "description": description,
            "params_schema": {"action": ACTION}, "exports": sorted(r["id"] for r in rules), "rules": rules,
            "defaults": {"action": "log"}}


def target_spec(target):
    return target if isinstance(target, tuple) else (target, None)


# ---------------------------------------------------------------- dedupe / false-positive filters
def add_contains(seen, doc):
    for r in doc["rules"]:
        match = (r.get("waf") or {}).get("match", {})
        if match.get("path") or match.get("method"):
            continue
        for item in match.get("inspect", []):
            if item["operator"] == "contains" and len(match["inspect"]) == 1:
                seen.setdefault((item["target"], item.get("key")), set()).update(v.lower() for v in item["values"])


def existing_contains():
    """(target, key) -> lower-case contains values of the 7 published official packs (single-clause rules)."""
    seen = {}
    for path in glob.glob(os.path.join(HERE, "rulepacks", "system-*.json")):
        add_contains(seen, json.load(open(path)))
    return seen


# Grows as packs are generated: a later pack does not repeat a feature of an earlier one.
EXISTING = existing_contains()


def covered(target, key, value):
    """An existing official contains rule on the same target already matches every request value matches."""
    return any(old in value.lower() for old in EXISTING.get((target, key), ()))


def legit_uas():
    if os.path.exists(UA_CACHE):
        return json.load(open(UA_CACHE))
    uas = set()
    with gzip.open(LEGIT, "rt") as f:
        for line in f:
            headers = json.loads(line).get("headers") or {}
            for name, value in headers.items():
                if name.lower() == "user-agent" and value:
                    uas.add(value)
    out = sorted(uas)
    json.dump(out, open(UA_CACHE, "w"))
    return out


def good_crawler_uas():
    """Sample UAs of the known-good crawlers (arcjet well-known-bots instances of every crawler in
    known-good-crawlers.json and the control plane default list)."""
    names = {c["name"] for c in json.load(open(os.path.join(HERE, "rulepacks", "known-good-crawlers.json")))["crawlers"]}
    defaults = json.load(open(os.path.join(HERE, "../../../libs/edgeconfig/crawlerdefaults/default.json")))
    for c in defaults["crawlers"]:
        names.add(c["name"])
        names.update(c.get("members", []))
    uas = []
    for bot in json.load(open(os.path.join(src("arcjet_well-known-bots"), "well-known-bots.json"))):
        if bot["id"].lower() in names:
            uas += bot.get("instances", {}).get("accepted", [])
    return sorted(set(uas))


# ---------------------------------------------------------------- naxsi
NAXSI_LINE = re.compile(r'^MainRule\s+(.*);\s*$')
NAXSI_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|(\S+)')


def naxsi_rules(path):
    out = []
    for line in open(path, errors="ignore"):
        m = NAXSI_LINE.match(line.strip())
        if not m:
            continue
        fields = {"negative": False}
        for quoted, bare in NAXSI_TOKEN.findall(m.group(1)):
            token = quoted if quoted or not bare else bare
            if bare == "negative":
                fields["negative"] = True
            elif token.startswith("id:"):
                fields["id"] = int(token[3:])
            elif token.startswith(("str:", "rx:", "mz:", "s:", "msg:")):
                head, _, value = token.partition(":")
                # nginx config quoting: \\ \" \' are unescaped, other backslashes kept (regex escapes)
                fields[head] = re.sub(r'\\([\\"\'])', r'\1', value)
        scores = {}
        for part in fields.get("s", "").split(","):
            name, _, value = part.partition(":")
            scores[name.lstrip("$")] = int(value)
        fields["scores"] = scores
        out.append(fields)
    return out


def naxsi_pattern(entry):
    """(operator, value) for a naxsi match: str → lower-case contains, rx → caseless regex."""
    if "str" in entry:
        return "contains", entry["str"]
    return "regex", entry["rx"]


def naxsi_zones(mz, table):
    """naxsi match zone → [(target, key)], extra match (path exact) or None when unsupported."""
    parts = mz.split("|")
    extra, zones = None, []
    names = set(parts)
    for part in parts:
        if part.startswith("$URL:"):
            extra = {"kind": "exact", "value": part[5:]}
        elif part.startswith("$ARGS_VAR:"):
            zones.append(("query", part[10:]))
        elif part in ("ARGS", "BODY") and table is BLOCK_ZONE:
            if "ARGS" in names and "BODY" in names:
                if ("args", None) not in zones:
                    zones.append(("args", None))
            else:
                zones.append(("query", None) if part == "ARGS" else ("body", None))
        elif part in table:
            for target in table[part]:
                spec = target_spec(target)
                if spec not in zones:
                    zones.append(spec)
        else:
            return None, None
    return zones, extra


def two_hit_regex(features):
    """A value holding two of features (the same one twice or two different ones)."""
    alt = "|".join(features)
    return "(?i)(?:%s)[\\s\\S]*(?:%s)" % (alt, alt)


def literal_regex(entry):
    op, value = naxsi_pattern(entry)
    return re.escape(value) if op == "contains" else "(?:%s)" % value


def naxsi_strong_candidates():
    """naxsi-core multi-character features as (target, key, operator, value, label) rules: every value of 2+
    characters of the single-feature contains rules, the SQL function regex, and each two-hit rule restricted to its
    multi-character alternatives. Single-character scoring features are left out."""
    _, doc = naxsi_core_pack()
    out = []
    for r in doc["rules"]:
        item = r["waf"]["match"]["inspect"][0]
        target, key = item["target"], item.get("key")
        if target == "upload_filename":
            continue
        if item["operator"] == "contains":
            out += [(target, key, "contains", v, TARGET_NAME[target] + "含 " + v) for v in item["values"] if len(v) >= 2]
        elif "-1r" in r["id"]:
            out.append((target, key, "regex", item["values"][0], r["name"]))
        else:
            m = re.match(r"^\(\?i\)\(\?:(.*)\)\[\\s\\S\]\*\(\?:", item["values"][0])
            alts = re.split(r"\|(?![^()]*\))", m.group(1))
            multi = [a for a in alts if len(re.sub(r"\\(.)", r"\1", a)) >= 2]
            if multi:
                out.append((target, key, "regex", "(?i)(?:%s)[\\s\\S]*(?:%s)" % ("|".join(multi), "|".join(multi)), r["name"]))
    return out


def naxsi_strong_pack():
    screen = json.load(open(os.path.join(HERE, "rulepacks", "imported", "naxsi-strong-screen.json")))
    keep = {(c["target"], c["operator"], c["value"]) for c in screen["candidates"] if c["selected"]}
    grouped = {}
    for target, key, op, value, label in naxsi_strong_candidates():
        if (target, op, value) not in keep:
            drop("naxsi_core", value[:80], "not a strong feature (single character, or >=0.5% of normal requests)")
            continue
        grouped.setdefault((target, key, op), []).append((value, label))
    rules = []
    for (target, key, op), items in sorted(grouped.items(), key=lambda kv: (kv[0][0], kv[0][2])):
        base = "naxsi-strong-" + target.replace("_", "-")
        if op == "contains":
            rules.append(rule(base + "-1", TARGET_NAME[target] + "含协议包装器/注释/逻辑运算特征",
                              [clause(target, "contains", sorted(v for v, _ in items), key)]))
        else:
            for index, (value, label) in enumerate(sorted(items)):
                rules.append(rule("%s-r%d" % (base, index), label, [clause(target, "regex", [value], key)]))
    return ("system-naxsi-strong.json", pack("naxsi-strong", "强注入特征（naxsi）",
            "参数、URL、Cookie 中的协议包装器（php:// phar:// gopher:// 等）、SQL 注释与 JSON 函数、URL/Cookie 内多处目录穿越或编码绕过"
            "等多字符强特征即记录，可改为拦截或挑战。只保留在大规模正常流量评测中单条命中低于 0.5% 的特征。", rules))


def naxsi_core_pack():
    entries = naxsi_rules(os.path.join(src("wargio_naxsi"), "naxsi_rules/naxsi_core.rules"))
    by_target = {}  # (target, key) -> category -> {"single": [...], "double": [...]}
    for entry in entries:
        zones, _ = naxsi_zones(entry["mz"], CORE_ZONE)
        if zones is None:
            drop("naxsi_core", entry["id"], "unsupported zone " + entry["mz"])
            continue
        if entry["id"] == 1315:
            drop("naxsi_core", 1315, "double encoding: the node URL-decodes values up to 3 times, %xx is never seen")
            continue
        for category, score in entry["scores"].items():
            need = THRESHOLD[category]
            kind = "single" if score >= need else "double" if 2 * score >= need else None
            if kind is None:
                drop("naxsi_core", "%d/%s" % (entry["id"], category), "score %d needs 3+ hits (cross-value sums not converted)" % score)
                continue
            for zone in zones:
                by_target.setdefault(zone, {}).setdefault(category, {"single": [], "double": []})[kind].append(entry)
    rules = []
    for (target, key), categories in sorted(by_target.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        base = "naxsi-" + target.replace("_", "-")
        label = TARGET_NAME[target]
        if "UPLOAD" in categories:
            for entry in categories.pop("UPLOAD")["single"]:
                if entry["negative"]:
                    # 文件名含 ^[.a-z0-9_\- ]+$ 以外的字符（naxsi negative rx 的等价正向写法）
                    rules.append(rule(base + "-name", label + "含非常规字符",
                                      [clause(target, "regex", ["(?i)[^.a-z0-9_ -]"], key)]))
                else:
                    rules.append(rule(base + "-ext", label + "为脚本/配置扩展名",
                                      [clause(target, "contains", sorted(v.lower() for v in alt_literals(entry["rx"])), key)]))
        # One feature, one place: a feature already enough on its own (in any category) is one contains / regex
        # rule of the target, and is left out of every two-hit set (a value holding it is matched already).
        singles = [e for groups in categories.values() for e in groups["single"] if not e["negative"]]
        contains = sorted({naxsi_pattern(e)[1].lower() for e in singles if naxsi_pattern(e)[0] == "contains"})
        kept = [v for v in contains if not covered(target, key, v)]
        for v in sorted(set(contains) - set(kept)):
            drop("naxsi_core", v, "already in an official pack on " + target)
        names = "/".join(CAT_NAME[c] for c in sorted(categories) if categories[c]["single"])
        if kept:
            rules.append(rule(base + "-1", "%s含 %s 特征" % (label, names), [clause(target, "contains", kept, key)]))
        regexes = sorted({"(?:%s)" % naxsi_pattern(e)[1] for e in singles if naxsi_pattern(e)[0] == "regex"})
        for index, pattern in enumerate(regex_chunks(regexes)):
            rules.append(rule("%s-1r%d" % (base, index), "%s含 SQL 函数特征" % label, [clause(target, "regex", [pattern], key)]))
        single_values = {naxsi_pattern(e)[1].lower() for e in singles}
        for category, groups in sorted(categories.items()):
            doubles = sorted({literal_regex(e) for e in groups["double"] if naxsi_pattern(e)[1].lower() not in single_values})
            if not doubles:
                continue
            pattern = two_hit_regex(doubles)
            if len(pattern) > MAX_REGEX:
                raise SystemExit("two-hit regex too long: %s %s" % (base, category))
            rules.append(rule("%s-2-%s" % (base, category.lower()), "%s同一值两处%s特征" % (label, CAT_NAME[category]),
                              [clause(target, "regex", [pattern], key)]))
    return ("system-naxsi-core.json", pack("naxsi-core", "通用注入特征（naxsi 核心）",
            "参数、URL、Cookie 中的 SQL 注入、远程文件包含、目录穿越、XSS、编码绕过特征与危险上传文件名；"
            "单个特征分数已达阈值的出现即命中，需两次命中的特征在同一个值里出现两处即命中。特征很宽（单个引号、括号即可命中），"
            "默认只记录，建议观察误报后再改为拦截或挑战。", rules))


def naxsi_blocking_pack(files, name, title, description, stem):
    groups = {}  # (target, key, operator, extra path) -> values
    for file in files:
        for entry in naxsi_rules(os.path.join(src("wargio_naxsi"), "naxsi_rules/blocking", file)):
            score = max(entry["scores"].values())
            if score < 8:
                drop("naxsi_" + stem, entry["id"], "score %d below 8 (only adds up with other rules)" % score)
                continue
            zones, extra = naxsi_zones(entry["mz"], BLOCK_ZONE)
            if zones is None:
                drop("naxsi_" + stem, entry["id"], "unsupported zone " + entry["mz"])
                continue
            if entry["id"] in NAXSI_REWRITE:
                original, rewritten = NAXSI_REWRITE[entry["id"]]
                assert entry["rx"] == original, entry["rx"]
                entry = dict(entry, rx=rewritten)
                stats["rewritten"].append({"id": entry["id"], "from": original, "to": rewritten})
            op, value = naxsi_pattern(entry)
            if not printable(value):
                drop("naxsi_" + stem, entry["id"], "pattern holds CR/LF (nginx refuses such URLs)")
                continue
            if op == "regex":
                unbounded, ok = regex_shape(value)
                if not ok or unbounded > MAX_UNBOUNDED:
                    drop("naxsi_" + stem, entry["id"], "regex not accepted by the node budget")
                    continue
            for target, key in zones:
                if op == "contains" and covered(target, key, value):
                    drop("naxsi_" + stem, value, "already in an official pack on " + target)
                    continue
                extra_key = json.dumps(extra, sort_keys=True) if extra else ""
                groups.setdefault((target, key or "", op, extra_key), []).append(value.lower() if op == "contains" else value)
    rules = []
    for (target, key, op, extra_key), values in sorted(groups.items()):
        extra = json.loads(extra_key) if extra_key else None
        label = TARGET_NAME[target] + ("[" + key + "]" if key else "")
        base = "%s-%s%s" % (stem, target.replace("_", "-"), "-" + re.sub(r"[^a-z0-9]+", "-", (extra or {}).get("value", "").lower()).strip("-")
                             if extra else "")
        if key:
            base += "-" + re.sub(r"[^a-z0-9]+", "-", key.lower())
        if op == "contains":
            for index, vals in enumerate(chunks(values)):
                rules.append(rule("%s-%02d" % (base, index), "%s含已知特征 第 %d 组" % (label, index + 1),
                                  [clause(target, "contains", vals, key or None)], path=extra))
        else:
            for index, pattern in enumerate(regex_chunks(["(?:%s)" % v for v in values])):
                rules.append(rule("%s-r%02d" % (base, index), "%s匹配已知特征 第 %d 组" % (label, index + 1),
                                  [clause(target, "regex", [pattern], key or None)], path=extra))
    return ("system-%s.json" % name, pack(name, title, description, rules))


def path_exemptions(rules):
    """naxsi whitelists/generic.rules: /robots.txt and /.well-known/security.txt are not probes; ACME HTTP-01
    tokens (/.well-known/acme-challenge/) are exempted the same way (a dot-file path otherwise)."""
    for r in rules:
        inspect = r["waf"]["match"].get("inspect", [])
        if any(item["target"] == "path" for item in inspect) and len(inspect) < 7:
            inspect.append(clause("path", "not_equals", ["/.well-known/security.txt", "/robots.txt"]))
            inspect.append(clause("path", "not_contains", ["/.well-known/acme-challenge/"]))
    return rules


# ---------------------------------------------------------------- device-detector
DD_SCRAPER = {"Crawler", "AI Data Scraper", "AI Assistant", "AI Search Crawler", "AI Agent", "Security Checker",
              "Security search bot", "Benchmark", "Search tools", "", None}
DD_PREFIX = r"(?:^|[^A-Z0-9_-]|[^A-Z0-9-]_|sprd-|MZ-)"  # device-detector AbstractParser::matchUserAgent


def dd_packs(benign_uas):
    bots = yaml.safe_load(open(os.path.join(src("matomo-org_device-detector"), "regexes/bots.yml")))
    lowered = [ua.lower() for ua in benign_uas]
    groups = {"scraper": {"contains": [], "regex": []}, "service": {"contains": [], "regex": []}}
    for bot in bots:
        pattern, category = bot["regex"], bot.get("category")
        group = groups["scraper" if category in DD_SCRAPER else "service"]
        literals = alt_literals(pattern)
        if literals is not None:
            for value in literals:
                low = value.lower()
                if len(low) < 3 or not printable(low):
                    drop("device_detector", value, "shorter than 3 / not printable")
                elif any(low in ua for ua in lowered):
                    drop("device_detector", value, "substring of a benign / known-good crawler User-Agent")
                elif covered("user_agent", None, low):
                    drop("device_detector", value, "already in an official UA pack")
                else:
                    group["contains"].append(low)
            continue
        unbounded, ok = regex_shape(pattern)
        if not ok or unbounded > MAX_UNBOUNDED or len(pattern) > MAX_REGEX - 20:
            drop("device_detector", pattern[:80], "lookaround / nested repetition / too long for the node regex budget")
            continue
        compiled = re.compile(DD_PREFIX + "(?:" + pattern + ")", re.I)
        if any(compiled.search(ua) for ua in benign_uas):
            drop("device_detector", pattern[:80], "matches a benign / known-good crawler User-Agent")
            continue
        group["regex"].append(pattern)
    out = []
    meta = {"scraper": ("bot-dd-scraper", "采集/AI/安全扫描 Bot（device-detector）", "dd-scraper",
                        "UA 含采集爬虫、AI 数据采集/助手、安全扫描类 Bot 标识即记录，可改为拦截或挑战。"),
            "service": ("bot-dd-service", "搜索/监控/服务类 Bot（device-detector）", "dd-service",
                        "UA 含搜索引擎（已知良性爬虫已剔除）、站点监控、服务代理、订阅抓取、链接预览、校验器等 Bot 标识即记录；"
                        "多为正常自动化访问，建议只记录或按需挑战。")}
    for key, (name, title, stem, description) in meta.items():
        rules = [rule("%s-%02d" % (stem, i), "%s 第 %d 组" % (title.split("（")[0], i + 1),
                      [clause("user_agent", "contains", vals)]) for i, vals in enumerate(chunks(groups[key]["contains"]))]
        # device-detector anchors every regex after a non-word character (or the start); kept as one prefix per chunk.
        for i, pattern in enumerate(regex_chunks(groups[key]["regex"], prefix="(?i)" + DD_PREFIX)):
            rules.append(rule("%s-r%02d" % (stem, i), "%s 正则第 %d 组" % (title.split("（")[0], i + 1),
                              [clause("user_agent", "regex", [pattern])]))
        stats[name] = {"contains": len(set(groups[key]["contains"])), "regex": len(groups[key]["regex"])}
        out.append(("system-%s.json" % name, pack(name, title, description, rules)))
    return out


# ---------------------------------------------------------------- bunkerweb
BW_OTHER_METHODS = ["CONNECT", "COPY", "DEBUG", "DELETE", "LOCK", "MKCOL", "MOVE", "OPTIONS", "PATCH", "PROPFIND",
                    "PROPPATCH", "PUT", "TRACE", "TRACK", "UNLOCK"]


def bw_pack():
    core = os.path.join(src("bunkerity_bunkerweb"), "src/common/core")
    settings = json.load(open(os.path.join(core, "misc/plugin.json")))["settings"]
    allowed = settings["ALLOWED_METHODS"]["default"].split("|")
    max_headers = int(settings["MAX_HEADERS"]["default"])
    size = settings["MAX_CLIENT_SIZE"]["default"]
    max_body = int(size[:-1]) * {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30}[size[-1].lower()]
    rules = [rule("bw-method-" + m.lower(), "方法 %s 不在允许列表" % m, None, method=m)
             for m in BW_OTHER_METHODS if m not in allowed]
    rules.append(rule("bw-header-count", "请求头超过 %d 个" % max_headers,
                      [clause("header_count", "gt", [str(max_headers)])]))
    rules.append(rule("bw-body-size", "请求体超过 %s" % size, [clause("body_length", "gt", [str(max_body)])]))
    # Bad UA (mitchellkrogza list) and bad behaviour (status burst) are already system/bot-bad-ua and
    # system/cc-404-burst; DNSBL / reverse scan / rDNS blacklists need lookups the WAF engine does not do.
    for item, reason in [("BLACKLIST_COMMUNITY_LISTS ua:mitchellkrogza-bad-user-agents", "same list as system/bot-bad-ua"),
                         ("BAD_BEHAVIOR 404", "system/cc-404-burst (cc_v2 counts 404 only; 400/401/403/405/429/444 not countable)"),
                         ("BLACKLIST_RDNS .shodan.io .censys.io", "waf_v2 has no reverse DNS condition"),
                         ("DNSBL / REVERSE_SCAN", "need network lookups")]:
        drop("bunkerweb", item, reason)
    return ("system-bw-request-limits.json", pack("bw-request-limits", "请求方法与大小限制",
            "方法不在 %s 之列、请求头超过 %d 个或请求体超过 %s 即记录，可改为拦截或挑战。OPTIONS 预检与 WebDAV/REST 站点"
            "（PUT/DELETE/PATCH）会命中，按站点关闭对应规则。" % ("/".join(allowed), max_headers, size), rules))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "rulepacks", "imported")
    os.makedirs(out, exist_ok=True)
    sys.path.insert(0, HERE)
    from gen_rulepacks import BROWSER_UAS
    benign = legit_uas() + good_crawler_uas() + BROWSER_UAS
    stats["benign_uas"] = len(benign)
    with open(os.path.join(out, "trusted-crawler-uas.json"), "w") as f:
        json.dump(good_crawler_uas(), f, ensure_ascii=False, indent=1)
    packs = [naxsi_strong_pack()]
    packs.append(naxsi_blocking_pack(["10000000_scanner.rules"], "naxsi-scanner", "扫描器特征（naxsi）",
                                     "UA、Accept、Content-Length 等含已知扫描器/攻击工具特征即记录，可改为拦截或挑战。"
                                     "含 curl、wget、python、Go-http 等通用客户端标识，API 调用方会命中。", "nx-scan"))
    websec = naxsi_blocking_pack(["20000000_web_security.rules", "30000000_wordpress.rules", "40000000_php_security.rules"],
                                 "naxsi-websec", "敏感路径与漏洞探测（naxsi）",
                                 "访问版本库/配置/备份/管理后台路径、已知漏洞入口、PHP 代码执行函数、XML-RPC 批量调用等即记录，"
                                 "可改为拦截或挑战。/robots.txt、/.well-known/security.txt、ACME 验证路径不命中。", "nx-web")
    path_exemptions(websec[1]["rules"])
    packs.append(websec)
    packs.append(naxsi_blocking_pack(["50000000_sql_injection.rules"], "naxsi-sqli", "SQL 注入函数特征（naxsi）",
                                     "参数、URL、请求头中的 xp_cmdshell、SLEEP(、BENCHMARK(、UNION…注释 等 SQL 注入函数特征即记录，"
                                     "可改为拦截或挑战。", "nx-sqli"))
    for _, doc in packs:
        add_contains(EXISTING, doc)
    packs += dd_packs(benign)
    packs.append(bw_pack())
    embedded = os.path.join(HERE, "../../../services/license-service/internal/licensing/officialpacks")
    for name, doc in packs:
        for directory in (out, embedded):
            with open(os.path.join(directory, name), "w") as f:
                json.dump(doc, f, ensure_ascii=False, indent=1)
        stats[name] = stats.get(name.replace("system-", "").replace(".json", ""), len(doc["rules"]))
    reasons = {}
    for item in stats["dropped"]:
        reasons[item["source"] + ": " + item["reason"]] = reasons.get(item["source"] + ": " + item["reason"], 0) + 1
    with open(os.path.join(out, "import-stats.json"), "w") as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in stats.items() if k != "dropped"}, ensure_ascii=False))
    print(json.dumps(reasons, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
