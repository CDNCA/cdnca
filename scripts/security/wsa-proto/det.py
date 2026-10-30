import re,base64,ipaddress,fnmatch,unicodedata
# ---- java_deser 增强：Base64 记号起始(对齐偏移 0..2 字节)即为 ObjectOutputStream 魔数 AC ED 00 05
ELEM=set([0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x79,0x7a,0x7b,0x7c,0x7d,0x7e])
def jmagic(v):
    for m in re.finditer(r'[A-Za-z0-9+/_\- ]{6,}', v):
        t=m.group(0).replace(' ','+').replace('-','+').replace('_','/')
        i=t.find('rO0AB');j=t.find('KztAA');k=t.find('Cs7QA')
        for pos,shift in ((i,0),(j,-1),(k,-2)):
            if pos<0 or (pos+shift)%4!=0 and not (pos==0 and shift<0): continue
            st=pos+shift if pos+shift>=0 else None
            if st is None:  # 片段从中间开始：补齐前导
                seg=('A'*(-shift-0)+t[pos:])
            else: seg=t[st:]
            seg=seg[:16]; seg=seg+'='*((4-len(seg)%4)%4)
            try: d=base64.b64decode(seg)
            except Exception: continue
            p=d.find(b'\xac\xed\x00\x05')
            if p>=0 and (p+4==len(d) or d[p+4] in ELEM): return True
    return False
# ---- ssrf：整值是 URL，主机为内网/回环/链路本地/元数据，或用了混淆编码
META={'metadata.google.internal','metadata.packet.net','metadata','instance-data','metadata.azure.com','100.100.100.200'}
BADSCHEME={'jar','file','gopher','dict','ldap','ldaps','local_file','jar','netdoc','tftp','php','expect','data','phar','sftp'}
def host_ip(h):
    h=h.strip('[]')
    try: return ipaddress.ip_address(h)
    except ValueError: pass
    parts=h.split('.')
    if not 1<=len(parts)<=4: return None
    nums=[]
    for p in parts:
        if re.fullmatch(r'0[xX][0-9a-fA-F]+',p): nums.append(int(p,16))
        elif re.fullmatch(r'0[0-7]+',p): nums.append(int(p,8))
        elif re.fullmatch(r'\d+',p): nums.append(int(p))
        else: return None
    if any(n<0 for n in nums): return None
    if len(nums)==1:
        n=nums[0]
        if n>0xffffffff: n&=0xffffffff
        return ipaddress.ip_address(n)
    *head,last=nums
    if any(x>255 for x in head) or last>=256**(5-len(nums)): return None
    v=0
    for x in head: v=v*256+x
    v=v*256**(5-len(nums))+last
    return ipaddress.ip_address(v)
def ssrf(v):
    s=v.strip()
    m=re.match(r'^([A-Za-z][A-Za-z0-9+.\-_]{1,15}):(//?)?(.*)$',s,re.S)
    if not m: return False
    scheme=m.group(1).lower()
    if scheme.startswith('url'): return ssrf(s[4:]) if s[:4].lower()=='url:' else False
    rest=m.group(3)
    if m.group(2) is None and scheme not in ('http','https'): return False
    if scheme in BADSCHEME: return True
    auth=re.split(r'[/?#]',rest,1)[0]
    raw=auth
    if '@' in auth: auth=auth.rsplit('@',1)[1]
    host=re.sub(r':\d*$','',auth)
    norm=unicodedata.normalize('NFKC',host).replace('。','.').lower()
    if norm!=host.lower() or '\\' in host: return True         # 全角/圈字/反斜杠混淆
    if ' ' in rest.split('/',1)[0] or raw.count('@')>1 or ('@' in raw and ('#' in rest or '&' in raw)): return True
    if norm in META or norm=='localhost' or norm.endswith('.localhost') or norm.endswith('.internal'): return True
    ip=host_ip(norm)
    if ip is None: return False
    if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+',norm) or any(len(p)>1 and p[0]=='0' for p in norm.split('.')): return True  # 非标准写法
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_reserved
# ---- cmd：shell 注入结构
CMDS=set('cat tac head tail less more nl ls dir id whoami uname hostname ifconfig ip netstat ps env printenv wget curl nc ncat netcat telnet ssh scp bash sh zsh dash ksh csh tcsh python python2 python3 perl ruby php lua node ping nslookup dig host traceroute chmod chown chgrp rm mv cp touch mkdir rmdir kill pkill killall sleep base64 xxd od dd find grep awk sed xargs crontab at nohup sudo su useradd adduser usermod passwd socat tftp ftp lwp-download fetch powershell cmd certutil bitsadmin systeminfo net reg whoami'.split())
SENS=['/etc/passwd','/etc/shadow','/etc/group','/etc/hosts','/etc/issue','/etc/sudoers','/proc/self/environ','/proc/self/cmdline','/proc/version','/bin/sh','/bin/bash','/bin/cat','/bin/nc','/usr/bin/id','/usr/bin/whoami','/bin/ls']
def unevade(w):
    w=re.sub(r"\$\{[^}]*\}|\$[A-Za-z_@*#?0-9]\w*|``|\$\(\)|''|\"\"|\\",'',w)
    return w
def word_cmd(w):
    raw=w; w=unevade(w).strip('\'"').lower()
    base=w.rsplit('/',1)[-1]
    if base in CMDS: return True, raw!=w and unevade(raw)!=raw
    if re.search(r'[?*\[]',base) and len(base)>=2:
        pat=base
        hit=[c for c in CMDS if fnmatch.fnmatchcase(c,pat)]
        if hit and re.search(r'[a-z]',pat): return True, True
    return False, False
def glob_sens(tok):
    t=unevade(tok).lower()
    if not re.search(r'[?*\[]',t) or not t.startswith('/') or t.count('/')<2 or len(re.findall(r'[a-z]',t))<2: return False
    return any(fnmatch.fnmatchcase(p,t) for p in SENS)
AMBIG=set('at id host find more head tail touch less net fetch ip kill sleep dir cat env nl od su sh ps rm mv cp dd ftp ping time date who which echo grep sort find kill top free make test true false read set export print type'.split())
WORDS=set('cat at more head tail touch less net fetch find kill sleep time date who which make test true false read set export print type host free top sort echo grep dir'.split())
ARG=re.compile(r"""^\s+(?:-{1,2}[A-Za-z]|\d+\s*$|[/~.]|\$|\d{1,3}\.\d{1,3}\.|[A-Za-z0-9._-]+\.(?:php|sh|txt|py|pl|jsp|asp|conf|log|so)\b|['"]?/)""")
SEP=r'(?:;|\|\|?|&&?|`|\$\()'
def cmd_at(s,start,word,sep=''):
    ok,ev=word_cmd(word)
    if not ok: return False
    w=unevade(word).strip('\'"').lower().rsplit('/',1)[-1]
    if w not in AMBIG or ev or '/' in word: return True
    rest=s[start:]
    if ARG.match(rest): return True
    if w not in WORDS and rest.strip()=='' : return True
    # bare word closed by a substitution: `id`, $(id)
    return sep in ('`','$(') and re.match(r'^\s*[`)]',rest) is not None
def cmd(v):
    s=v.replace('```','')
    if re.search(r'([\w:]+)\s*\(\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1',s): return True
    for m in re.finditer(r'\{([^{}]*,[^{}]*)\}',s):
        parts=[p for p in m.group(1).split(',') if p]
        if parts and word_cmd(parts[0].strip("$'\""))[0]: return True
    for tok in re.split(r'[\s;|&`()<>]+',s):
        if glob_sens(tok): return True
    for m in re.finditer('('+SEP+r')\s*((?:\$[A-Za-z_]\w*\s+)*)([^\s;|&`()<>]+)',s):
        if cmd_at(s,m.end(),m.group(3),m.group(1)): return True
    m=re.match(r'^\s*([^\s;|&()<>]+)',s)
    if m:
        ok,ev=word_cmd(m.group(1))
        if ok and ev: return True
    return False
