# 灰区下限扫描（RI-03 第 4 项）：用 eval 留存的逐条命中规则向量离线重算
# 严格/极严格的两级评分，灰区挑战条件由“某集合 0 < 总分 < 弱阈值”改为
# “某集合 下限 <= 总分 < 弱阈值”，拦截不变，只看挑战集合的变化。
# 先核对下限=1（现行）时离线结果与真实 OpenResty 逐条一致，再扫描。
# 用法：python3 greyfloor.py data/eval-ri03.jsonl.gz
import sys
from sim import OWN, SEV, crs, load

# edgeconfig DynamicWAFDetectors（sim.DET 缺 ssrf/cmd）
DET = {'sqli': 'crs_sqli', 'xss': 'crs_xss', 'ssti': 'crs_ssti', 'java_deser': 'crs_java_deserialization',
       'php_deser': 'crs_php_deserialization', 'ssrf': 'crs_file_include', 'cmd': 'crs_cmd_injection'}

WEAK, STRONG = 10, 5


def sums(rules, pack, pl, detectors):
    own, _ = OWN[pack]
    strong, weak = {}, {}
    for r in rules:
        if r not in own or crs[r][0] > pl:
            continue
        k, s = own[r], SEV[crs[r][1]]
        if crs[r][0] > 1:
            weak[k] = weak.get(k, 0) + s
        else:
            strong[k] = strong.get(k, 0) + s
    for d in detectors:
        if d in DET:
            strong[DET[d]] = strong.get(DET[d], 0) + 5
    return strong, weak


def judge(row, pack, pl, floor):
    strong, weak = sums(row['rules'], pack, pl, row.get('detectors') or [])
    keys = set(strong) | set(weak)
    if any(strong.get(k, 0) >= STRONG or strong.get(k, 0) + weak.get(k, 0) >= WEAK for k in keys):
        return 'block'
    if any(strong.get(k, 0) + weak.get(k, 0) >= floor for k in keys):
        return 'challenge'
    return 'pass'


def browser(row, index, pack, pl):
    # 真实环境下限=1 时放行、离线判挑战的请求不是浏览器类（API 类 POST
    # 永不挑战，adapt.browser）：扫描时同样不挑战
    return not (not row['tiers'][index] and not row['challenged'][index] and judge(row, pack, pl, 1) == 'challenge')


def verdict(row, index, pack, pl, floor):
    result = judge(row, pack, pl, floor)
    return 'pass' if result == 'challenge' and not browser(row, index, pack, pl) else result


def main(path):
    rows = load(path)
    attacks = [r for r in rows if r['attack']]
    benign = [r for r in rows if not r['attack']]
    for index, name, pack, pl in ((2, '严格', 'crs-pl2', 2), (3, '极严格', 'crs-pl3', 3)):
        same = sum(1 for r in rows if (verdict(r, index, pack, pl, 1) == 'block') == r['tiers'][index] and
                   (verdict(r, index, pack, pl, 1) == 'challenge') == r['challenged'][index])
        print('== %s 离线与实测逐条一致 %d/%d' % (name, same, len(rows)))
        print('| 下限 | 拦截 | 拦截+挑战 | 误报(拦截) | 正常被挑战 | 攻击被挑战 |')
        print('|---|---|---|---|---|---|')
        for floor in (1, 3, 4, 5, 6, 7, 8, 9):
            a = [verdict(r, index, pack, pl, floor) for r in attacks]
            b = [verdict(r, index, pack, pl, floor) for r in benign]
            print('| %d | %.2f%% | %.2f%% | %.2f%% | %.2f%% (%d) | %d |' % (
                floor, 100.0 * a.count('block') / len(a), 100.0 * (len(a) - a.count('pass')) / len(a),
                100.0 * b.count('block') / len(b), 100.0 * b.count('challenge') / len(b), b.count('challenge'),
                a.count('challenge')))


if __name__ == '__main__':
    main(sys.argv[1])
