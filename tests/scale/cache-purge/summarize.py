#!/usr/bin/env python3
# Summarize SCALE_RESULT lines: tests/scale/cache-purge/summarize.py <results.jsonl>
import json,sys
for l in open(sys.argv[1] if len(sys.argv)>1 else '/tmp/purge-scale/results.jsonl'):
    d=json.loads(l)
    n=d['target']+d['other']
    extra=''
    if 'sync' in d: extra+=' sync=%s'%{k:v for k,v in d['sync'].items() if v}
    if 'index_mb' in d: extra+=' index=%.0fMB'%d['index_mb']
    print('%-16s %-10s %8.2fs  aff=%-8d files=%-8d us/file=%6.1f rd=%7.0fMB rchar=%6.0fMB syscr=%-9d cpu=%.1f+%.1fs rss=%4dMB heap=%5.1fMB %s'%(
      d['label'],d['scenario'],d['seconds'],d['affected'],n,d['seconds']*1e6/n,d['read_bytes_mb'],d['rchar_mb'],d['syscr'],d['user_s'],d['sys_s'],d['maxrss_kb']//1024,d['heap_peak_mb'],d['error'][:50])+extra)
