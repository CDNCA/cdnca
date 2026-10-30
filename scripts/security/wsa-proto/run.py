# waf-strict-algo 离线评测原型（不进产品）：用 eval 日志里 probe 记录的 PL4 命中规则向量，
# 按档位包集归属 + 两级评分（W=10）重算严格/极严格拦截，并叠加 det.py 新检测器作强信号。
# 用法：python3 run.py [java_deser,ssrf,cmd] [-lost] [-show 931130,932239]
# 数据：data/eval-{before,after,2b}.jsonl.gz = 真实 OpenResty ONLY=eval 的 EVAL 行；
#       data/crs-rules.json = CRS 4.30 规则 PL/严重度/文件；data/lost-2b.txt = 2b 相对改前严格档漏拦样本。
# 换数据：WSA_AFTER=/tmp/x.log WSA_BEFORE=... python3 run.py
import json,collections,sys,os
HERE=os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0,HERE)
from src import *; import det
__file__=os.path.join(HERE,'sim.py'); exec(open(__file__).read().split("if __name__")[0])
rows=load(os.environ.get('WSA_AFTER',HERE+'/data/eval-2b.jsonl.gz')); b={r['id']:r for r in load(os.environ.get('WSA_BEFORE',HERE+'/data/eval-before.jsonl.gz'))}
NEW={'java_deser':det.jmagic,'ssrf':det.ssrf,'cmd':det.cmd}
SET={'java_deser':'crs_java_deserialization','ssrf':'crs_file_include','cmd':'crs_cmd_injection'}
use=sys.argv[1].split(',') if len(sys.argv)>1 else list(NEW)
fire=collections.defaultdict(lambda:[0,0]); fpd=[]
def ext(r):
    e={DET[d]:5 for d in r['detectors']}
    for n in use:
        if any(NEW[n](x) for x in args_values(r)):
            e[SET[n]]=5; fire[n][0 if r['attack'] else 1]+=1
            if not r['attack']: fpd.append((n,r['id'],args_values(r)[:2]))
    return e
for r in rows: r['x']=ext(r)
A=[r for r in rows if r['attack']]; B=[r for r in rows if not r['attack']]
for nm,pk,pl in (('严格','crs-pl2',2),('极严格','crs-pl3',3)):
    tp=sum(blocked(r['rules'],pk,pl,10,r['x']) for r in A); fp=sum(blocked(r['rules'],pk,pl,10,r['x']) for r in B)
    print(nm,'TPR %d/%d=%.4f FPR %d/%d=%.4f'%(tp,len(A),tp/len(A),fp,len(B),fp/len(B)))
print(dict(fire)); print(fpd[:20])
if '-lost' in sys.argv:
    still=[r for r in A if b[r['id']]['tiers'][2] and not blocked(r['rules'],'crs-pl2',2,10,r['x'])]
    gain=[r for r in A if not b[r['id']]['tiers'][2] and blocked(r['rules'],'crs-pl2',2,10,r['x'])]
    print('still lost',len(still),'new gains',len(gain))
    c=collections.Counter(r['id'].split('-')[1] for r in still); print(c.most_common(25))
    src=collections.Counter(('A' if args_values(r) and any(args_values(r)) else '')+('H' if [x for x in header_values(r) if x!='OWASP CRS test agent'] else '')+('P' if path_value(r) not in('/get','/post','/','') else '') for r in still); print(src)
if '-show' in sys.argv:
    pre=sys.argv[sys.argv.index('-show')+1].split(',')
    for r in A:
        if b[r['id']]['tiers'][2] and not blocked(r['rules'],'crs-pl2',2,10,r['x']) and r['id'].split('-')[1] in pre:
            print(r['id'],args_values(r)[:3],[x for x in header_values(r) if x!='OWASP CRS test agent'][:2],path_value(r)[:60],r['rules'])
