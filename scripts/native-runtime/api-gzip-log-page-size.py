#!/usr/bin/env python3
"""Estimates the bytes a log center access-log page (GET /v1/analytics/logs/access)
saves with the management nginx JSON gzip (api-gzip, 10-31).

The page is synthetic but uses the response's real field set
(services/control-api/internal/analyticslog/model.go AccessLog) and
high-entropy IDs, so the ratio is a conservative estimate. Output: raw and
gzip bytes for 20/50/100 items at comp_level 1/4/5/6 (nginx uses 5).
"""
import json
import random
import uuid
import zlib

random.seed(7)


def uid():
    return str(uuid.UUID(int=random.getrandbits(128), version=4))


SITES = [uid() for _ in range(3)]
NODES = [uid() for _ in range(4)]
PATHS = ['/', '/index.html', '/api/v1/products', '/static/app.3f9a1c.js', '/images/banner.webp', '/login', '/api/v1/cart/items']


def item(i):
    return {
        'event_id': uid(), 'occurred_at': '2026-10-30T12:%02d:%02d.%03dZ' % (i % 60, random.randrange(60), random.randrange(1000)),
        'site_id': random.choice(SITES), 'node_id': random.choice(NODES), 'request_id': uid(),
        'trace_id': '%032x' % random.getrandbits(128), 'config_version_id': uid(), 'host': 'www.example.test',
        'listen_port': 443, 'uri_path': random.choice(PATHS),
        'client_ip': '%d.%d.%d.%d' % (random.randrange(1, 223), random.randrange(256), random.randrange(256), random.randrange(1, 255)),
        'country_code': random.choice(['CN', 'US', 'HK', 'SG']), 'carrier': random.choice(['电信', '联通', '移动', '']),
        'method': random.choice(['GET', 'GET', 'GET', 'POST']), 'protocol': random.choice(['HTTP/2.0', 'HTTP/1.1', 'HTTP/3.0']),
        'cache_status': random.choice(['HIT', 'MISS', 'BYPASS']), 'upstream_result': 'ok',
        'upstream_addr': '203.0.113.%d:443' % random.randrange(1, 20), 'status_code': random.choice([200, 200, 200, 304, 404]),
        'request_bytes': random.randrange(200, 1800), 'response_bytes': random.randrange(300, 900000),
        'duration_us': random.randrange(300, 900000), 'task_id': None, 'installation_id': uid(),
        'request_headers': {}, 'response_headers': {}, 'request_body': {}, 'response_body': {},
        'ja4': 't13d1516h2_8daaf6152771_%012x' % random.getrandbits(48),
        'origin_connect_us': random.randrange(100, 9000), 'origin_first_byte_us': random.randrange(1000, 90000),
        'origin_total_us': random.randrange(1000, 900000),
    }


def gzip_size(body, level):
    return len(zlib.compress(body, level)) - 6 + 18  # zlib header/adler32 -> gzip header/crc32/isize


for count in (20, 50, 100):
    body = json.dumps({'items': [item(i) for i in range(count)], 'next_cursor': 'eyJ%064x' % random.getrandbits(256),
                       'snapshot_at': '2026-10-30T12:59:59Z'}, ensure_ascii=False, separators=(',', ':')).encode()
    sizes = {level: gzip_size(body, level) for level in (1, 4, 5, 6)}
    print(f'items={count:3d} raw={len(body):6d} ' + ' '.join(f'gzip{k}={v:6d}' for k, v in sizes.items()) +
          f' level5={sizes[5] / len(body):.0%}')
