# 离线模拟：用 probe 记录的 PL4 命中规则向量，按档位包集归属与两级评分重算拦截
import json,sys,os,gzip
HERE=os.path.dirname(os.path.abspath(__file__))
W=os.path.join(HERE,'../../../libs/rulepack/testdata/crs-profiles/')
crs={int(k):v for k,v in json.load(open(os.path.join(HERE,'data/crs-rules.json'))).items()}
SEV={'critical':5,'error':4,'warning':3,'notice':2}
def owner(pack):
    sets=json.load(open(W+pack+'.json'))['rules']; own={}
    for s in sets:
        c=s['crs']
        for rid,(pl,sev,f) in crs.items():
            if any(f.startswith(p) for p in c['files']) and rid not in c['exclude_ids']: own[rid]=s['id']
    for s in sets:
        for rid in s['crs']['include_ids']:
            if rid in crs: own[rid]=s['id']
    return own,{s['id']:s['crs'] for s in sets}
OWN={p:owner(p) for p in ['crs-pl1','crs-pl2','crs-pl3']}
def blocked(rules,pack,pl,W2,extra=None):
    own,sets=OWN[pack]; strong={};weak={}
    for r in rules:
        if r not in own or crs[r][0]>pl: continue
        k=own[r]; s=SEV[crs[r][1]]
        if W2 and crs[r][0]>1: weak[k]=weak.get(k,0)+s
        else: strong[k]=strong.get(k,0)+s
    for k,v in (extra or {}).items(): strong[k]=strong.get(k,0)+v
    for k in set(strong)|set(weak):
        if strong.get(k,0)>=5: return True
        if W2 and strong.get(k,0)+weak.get(k,0)>=W2: return True
    return False
def load(path):
    f=gzip.open(path,'rt') if path.endswith('.gz') else open(path)
    return [json.loads(l[5:]) for l in f if l.startswith('EVAL ')]
DET={'ssti':'crs_ssti','java_deser':'crs_java_deserialization','php_deser':'crs_php_deserialization','sqli':'crs_sqli','xss':'crs_xss'}
def table(rows,cfgs,label):
    print('==',label)
    for name,fn in cfgs:
        tp=sum(1 for r in rows if r['attack'] and fn(r)); a=sum(1 for r in rows if r['attack'])
        fp=sum(1 for r in rows if not r['attack'] and fn(r)); b=sum(1 for r in rows if not r['attack'])
        print('%-28s TPR %d/%d=%.4f  FPR %d/%d=%.4f'%(name,tp,a,tp/max(a,1),fp,b,fp/max(b,1)))
if __name__=='__main__':
    rows=load(sys.argv[1])
    cfgs=[('real 仅记录',lambda r:r['tiers'][0]),('real 标准',lambda r:r['tiers'][1]),('real 严格',lambda r:r['tiers'][2]),('real 极严格',lambda r:r['tiers'][3]),
          ('sim 标准',lambda r:blocked(r['rules'],'crs-pl1',1,0)),
          ('sim 严格 单级',lambda r:blocked(r['rules'],'crs-pl2',2,0)),('sim 极严格 单级',lambda r:blocked(r['rules'],'crs-pl3',3,0))]
    for w in (10,15,20):
        cfgs+=[('sim 严格 W=%d'%w,lambda r,w=w:blocked(r['rules'],'crs-pl2',2,w)),('sim 极严格 W=%d'%w,lambda r,w=w:blocked(r['rules'],'crs-pl3',3,w))]
    for w in (10,15,20):
        cfgs+=[('sim 严格 W=%d +det'%w,lambda r,w=w:blocked(r['rules'],'crs-pl2',2,w,{DET[d]:5 for d in r['detectors']})),
               ('sim 极严格 W=%d +det'%w,lambda r,w=w:blocked(r['rules'],'crs-pl3',3,w,{DET[d]:5 for d in r['detectors']}))]
    table(rows,cfgs,sys.argv[1])
    agree=[sum(1 for r in rows if r['tiers'][i]==blocked(r['rules'],p,pl,ww)) for i,p,pl,ww in ((1,'crs-pl1',1,0),(2,'crs-pl2',2,int(sys.argv[2])),(3,'crs-pl3',3,int(sys.argv[2])))]
    print('sim 与实测一致', agree, '/', len(rows))
