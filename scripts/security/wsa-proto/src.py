import json,urllib.parse as u,collections
STD={'accept','accept-encoding','accept-language','host','content-type','keep-alive','proxy-connection','connection','content-length','cache-control'}
def dec(s):
    for _ in range(4):
        n=u.unquote_plus(s) if False else u.unquote(s.replace('+',' '))
        if n==s: break
        s=n
    return s
def args_values(r):
    out=[]
    if 'value' in r and r.get('value') and not r.get('uri'):
        return [r['value']]   # built-in: sent as ?v= and form v=
    uri=r.get('uri') or ''
    q=uri.split('?',1)[1] if '?' in uri else ''
    for p in q.split('&'):
        if not p: continue
        k,_,v=p.partition('='); out.append(dec(k)); 
        if '=' in p: out.append(dec(v))
    body=r.get('data') or ''
    ct=((r.get('headers') or {}).get('Content-Type') or '').lower()
    if body:
        if 'x-www-form-urlencoded' in ct:
            for p in body.split('&'):
                k,_,v=p.partition('='); out.append(dec(k))
                if '=' in p: out.append(dec(v))
        elif 'json' in ct:
            try:
                def walk(x):
                    if isinstance(x,str): out.append(dec(x))
                    elif isinstance(x,dict):
                        for k,v in x.items(): out.append(dec(k)); walk(v)
                    elif isinstance(x,list):
                        for v in x: walk(v)
                walk(json.loads(body))
            except Exception: out.append(dec(body))
        else: out.append(dec(body))
    return out
def header_values(r):
    out=[]
    for k,v in (r.get('headers') or {}).items():
        lk=k.lower()
        if lk in STD: continue
        if lk=='cookie':
            for p in v.split(';'):
                a,_,b=p.strip().partition('='); out.append(dec(a)); out.append(dec(b))
        else: out.append(dec(v))
    return out
def path_value(r):
    uri=r.get('uri') or ''
    return dec(uri.split('?',1)[0])

