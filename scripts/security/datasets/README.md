# 公开 WAF 评测数据集（cdnca-waf-check -corpus-set std）

数据只在本机使用，不进仓库、不外传。原始包和转换产物放 `~/.cache/cdnca-waf-datasets/`（`raw/`、`corpus/`），仓库只放脚本与本说明。

## 来源、版本、许可、校验

| 数据集 | 来源 | 版本 / 提交 | 许可 | 文件 SHA-256 |
|---|---|---|---|---|
| waf-comparison 正常请求（1,040,242 条，692 个文件） | https://downloads.openappsec.io/waf-comparison-project/legitimate.zip （工具仓库 https://github.com/openappsec/waf-comparison-project ） | zip Last-Modified 2024-12-01；工具 8ec8263eebba76816601f7c7052f8ffb83e31312（2026-02-11） | Apache-2.0（仓库 LICENSE 与 README："tooling and the Legitimate dataset"） | legitimate.zip `58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778` |
| waf-comparison 攻击（73,924 条，7 类） | https://downloads.openappsec.io/waf-comparison-project/malicious.zip （源自 https://github.com/mgm-sp/WAF-Payload-Collection ） | zip Last-Modified 2023-07-17 | README："different copyrights, mostly under MIT" | malicious.zip `131314e5c13b07ec686e6b16b8010008063d977b5ff8eb552819c138c00b7b2b` |
| GoTestWAF 用例（攻击 675、正常 141，按 payload × 编码 × 位置展开） | https://github.com/wallarm/gotestwaf testcases/ | 8ed7bc210ab7530c83b00e591136847307635207（2026-09-25） | MIT | gotestwaf-cases.json（yaml.v2 导出）`39ee5cf59c0e1d0122a2c80e56ac1751660f935d3acdb80097521beeafe04ffb` |
| Leipzig eng_news_2023_100K（10 万英文新闻句） | https://downloads.wortschatz-leipzig.de/corpora/eng_news_2023_100K.tar.gz （go-ftw quantitative 默认语料：https://github.com/coreruleset/go-ftw ） | build 2024-01-12；go-ftw b2dfd8884efecd5e20a0eb433d88a39cac9e83e0（2026-10-09） | 使用条款 https://wortschatz.uni-leipzig.de/en/usage ："permission for use is granted free of charge solely for non-commercial personal and scientific purposes"（页面有反爬，原文经搜索摘要核对）。**只作内部评测，不得随产品分发** | `8e65ed5b9c96687d293374335c14dfb9db4c150877bcc208a21bcb2f86b43484` |

## 拉取与转换

```sh
C=~/.cache/cdnca-waf-datasets
mkdir -p $C/raw
curl -sSL -o $C/raw/malicious.zip  https://downloads.openappsec.io/waf-comparison-project/malicious.zip
curl -sSL -o $C/raw/legitimate.zip https://downloads.openappsec.io/waf-comparison-project/legitimate.zip   # 1.2 GB；慢时用 curl -r 分段并行再拼接
curl -sSL -o $C/raw/eng_news_2023_100K.tar.gz https://downloads.wortschatz-leipzig.de/corpora/eng_news_2023_100K.tar.gz
git clone https://github.com/wallarm/gotestwaf $C/gotestwaf && git -C $C/gotestwaf checkout 8ed7bc210ab7530c83b00e591136847307635207
printf '%s  %s\n' 58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778 $C/raw/legitimate.zip \
  131314e5c13b07ec686e6b16b8010008063d977b5ff8eb552819c138c00b7b2b $C/raw/malicious.zip \
  8e65ed5b9c96687d293374335c14dfb9db4c150877bcc208a21bcb2f86b43484 $C/raw/eng_news_2023_100K.tar.gz | shasum -a 256 -c -
# GoTestWAF 用例按它自己的 yaml.v2 解析导出（PyYAML 不接受用例里的 \' 等转义）
mkdir -p $C/gotestwaf/cmd/cdnca-dump && cp scripts/security/datasets/gotestwaf-dump.go.txt $C/gotestwaf/cmd/cdnca-dump/main.go
GOWORK=off GOFLAGS=-mod=mod go -C $C/gotestwaf run ./cmd/cdnca-dump $C/gotestwaf/testcases > $C/raw/gotestwaf-cases.json
python3 -m venv $C/venv && $C/venv/bin/pip install requests==2.32.3 PyYAML==6.0.2
$C/venv/bin/python scripts/security/datasets/convert.py $C          # 产出 $C/corpus/*.jsonl.gz，约 1 分钟
```

## 转换口径（尽量与各项目自己的客户端一致，便于和公开报告比）

- **wafcomp-mal / wafcomp-legit**：按 waf-comparison 的 `helper.send_request`（python requests 2.32.3）复现实际发出的请求，包括去 Host、requests 对 URL 的重新转义、默认头（UA 等以记录为准）、str 请求体按 ISO-8859-1 发送。requests 本身会抛错的请求，项目记 status 0 并在指标 SQL 中排除（`response_status_code != 0`），我们同样在转换时排除：正常 6,603 条、攻击 0 条。`fast` 字段复现其 `--fast` 抽样（每个文件 seed 42 洗牌后取 15%）。
- **gotestwaf**：payload × encoder × placeholder，与 `internal/payload` 一致：URL=PathEscape，Base64Flat 去 `=`，JSONRequest 再套 JSUnicode，SOAPBody 套 XMLEntity，加 config.yaml 默认头。随机参数名改为确定性 10 位 hex。GraphQL 与 gRPC 默认运行不发（需要 -graphqlURL/-grpcPort），这里同样跳过（6 条）。判定口径同其默认值：403 记拦截，200/404 记放行，其余记 unresolved 不计入。
- **leipzig**：按 go-ftw quantitative，`GET /get?uri_payload=<QueryEscape(句子)>`（category query），并额外以同一文本作 form 体（category form）。go-ftw 本身只发 query。
- 拦截一律按 403 判定（两个项目的默认值；waf-comparison 另认 F5 拦截页文字，与我们无关）。

## 运行

```sh
env ONLY=eval CORPUS_SET=std STD_SETS=gotestwaf sh tests/dynroute-waf/run.sh > /tmp/x.log
grep -E '^(STD|STDBA|STDTIME|RESULT)' /tmp/x.log
```

大数据集用 `STD_SHARD=i/n` 分批，单批不超过 10 分钟，再把各批的 STD 行相加。`STD_FAST=1` 只跑 waf-comparison 的 --fast 子集。
