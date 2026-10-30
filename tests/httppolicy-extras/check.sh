#!/bin/sh
# Inside the container: openresty -t, start, request cases.
set -u
mkdir -p /tmp/hp
fail=0
openresty -p /tmp/hp/ -c /hp/nginx.conf -t >/tmp/hp/t.log 2>&1 && echo "PASS openresty-t" || { echo "FAIL openresty-t"; cat /tmp/hp/t.log; exit 1; }
openresty -p /tmp/hp/ -c /hp/nginx.conf
sleep 0.5
# h <path> [header line]...: the raw response head over HTTP/1.1 (nc)
h() {
	path=$1; shift
	# busybox nc closes the socket at the end of stdin: keep it open briefly
	{ printf 'GET %s HTTP/1.1\r\nConnection: close\r\n' "$path"; for line in "$@"; do printf '%s\r\n' "$line"; done; printf '\r\n'; sleep 0.3; } |
		nc -w 3 127.0.0.1 18301 | tr -d '\r' | sed '/^$/q'
}
expect() { # name, headers, pattern
	if printf '%s\n' "$2" | grep -Eq "$3"; then echo "PASS $1"; else echo "FAIL $1 want /$3/"; printf '%s\n' "$2" | sed 's/^/    /'; fail=1; fi
}
reject() {
	if printf '%s\n' "$2" | grep -Eq "$3"; then echo "FAIL $1 must not match /$3/"; printf '%s\n' "$2" | sed 's/^/    /'; fail=1; else echo "PASS $1"; fi
}
r=$(h '/plain?q=1' 'Host: hp.test' 'User-Agent: Mozilla/5.0' 'X-Multi: client' 'X-Once: client')
expect VAR-REMOTE-ADDR "$r" '^X-Echo-x-client: 127\.0\.0\.1$'
expect VAR-UA "$r" '^X-Echo-x-ua: Mozilla/5\.0$'
expect VAR-TLS-FP "$r" '^X-Echo-x-fp: t13d1516h2_8daaf6152771_b186095e22b6$'
expect VAR-IPLIB-ABSENT-EMPTY "$r" '^X-Echo-x-geo: c=;p=;a=;i=$'
expect VAR-LITERAL-DOLLAR-AND-SUFFIX "$r" '^X-Echo-x-lit: cost \$5 hp\.test-x$'
expect ALLOW-DUPLICATE-APPENDS "$r" '^X-Echo-x-multi: client\|edge$'
expect NO-DUPLICATE-KEEPS-CLIENT "$r" '^X-Echo-x-once: client$'
expect RESP-ALLOW-DUPLICATE "$r" '^[Xx]-[Rr]esp-[Mm]ulti: edge-GET$'
expect RESP-ALLOW-DUPLICATE-ORIGIN-KEPT "$r" '^X-Resp-Multi: origin$'
expect RESP-NO-DUPLICATE-ORIGIN-ONLY "$r" '^X-Resp-Once: origin$'
reject RESP-NO-DUPLICATE-NOT-ADDED "$r" '^X-Resp-Once: edge$'
expect RESP-VARS "$r" '^[Xx]-[Rr]esp-[Nn]ew: http://hp\.test/plain$'
# header injection: control bytes of a request value never reach the
# origin (nginx refuses raw CR/LF itself); a long value is cut at 1024
r=$(h /plain 'Host: hp.test' "$(printf 'User-Agent: a\tb\001c')")
expect VAR-CONTROL-BYTES-DROPPED "$r" '^X-Echo-x-ua: abc$'
long=$(head -c 3000 /dev/zero | tr '\0' 'x')
r=$(h /plain 'Host: hp.test' "User-Agent: $long")
got=$(printf '%s\n' "$r" | sed -n 's/^X-Echo-x-ua: //p')
if [ "${#got}" -eq 1024 ]; then echo "PASS VAR-TRUNCATED-1024"; else echo "FAIL VAR-TRUNCATED-1024 length ${#got}"; fail=1; fi
r=$(h /plain 'Host: hp.test')
reject VAR-EMPTY-SET-REMOVED "$r" '^X-Echo-x-ua:'
# conditions: rewrite only for mobile UA
r=$(h '/app/x?k=1' 'Host: hp.test' 'User-Agent: iPhone')
expect COND-UA-REWRITE "$r" '^X-Origin-Uri: /m/x\?k=1$'
r=$(h /app/x 'Host: hp.test' 'User-Agent: Mozilla')
expect COND-UA-NO-MATCH "$r" '^X-Origin-Uri: /app/x$'
r=$(h /beta 'Host: hp.test' 'X-Beta: 1')
expect COND-HEADER-AND-HOST "$r" '^X-Origin-Uri: /beta-on$'
r=$(h /beta 'Host: other.test' 'X-Beta: 1')
expect COND-ALL-MUST-MATCH "$r" '^X-Origin-Uri: /beta$'
r=$(h /any 'Host: hp.test' 'Referer: https://spam.test/x')
expect COND-REFERER-REDIRECT "$r" '^HTTP/1\.1 302' 
expect COND-REFERER-REDIRECT-LOCATION "$r" '^Location: https://www\.example\.test/blocked$'
r=$(h /any 'Host: hp.test' 'Referer: https://good.test/x')
expect COND-REFERER-NO-REDIRECT "$r" '^HTTP/1\.1 200'
if grep -E '\[(error|crit|alert|emerg)\]' /tmp/hp/error.log; then echo "FAIL error-log"; fail=1; else echo "PASS error-log-clean"; fi
openresty -p /tmp/hp/ -c /hp/nginx.conf -s stop
echo "RESULT failures=$fail"
exit $fail
