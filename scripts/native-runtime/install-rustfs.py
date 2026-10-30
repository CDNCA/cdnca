#!/usr/bin/env python3
"""Fresh amd64 RustFS (official static musl build) only; caller downloads and verifies this helper.

check/install/preflight --archive ROOT_PRIVATE_ZIP. No activation, downloads,
application flags, customer data, existing installation, or existing CA is changed.
Failed installation stops its new service and removes only its own added CA; all
private configuration/data remain for diagnosis. Re-running install then refuses.
"""

import argparse
import contextlib
import datetime
import fcntl
import grp
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile

# Fresh installs use the official static musl build (no glibc floor, verified to
# run from CentOS 7 to Debian 13). Hosts installed before 2026-10-15 carry the
# official gnu build; their receipts stay valid and are never rewritten.
ARCHIVE_SHA = "a834096dafa1f1a55825a2cdaf49d006a193978d344f2d508c2be475133738a3"
BINARY_SHA = "a5ac41209ca8eca6c591c1584cc108b308850e1b74955afd4af9fe1b0379f2eb"
ARCHIVE_MEMBERS = {"rustfs", "rustfs-cli"}
LEGACY_RECEIPTS = ({"archive_sha256": "9742e183cb0dfb0d48fa909797af572fe47b7f827569036baa4156e0d3958ee5",
                    "binary_sha256": "e6544a42a09a16d6fea47ad3d8aaa1a8793c9afa9c723bb8ae884f1238cd7c25"},)
CONFIG = Path("/etc/cdnca-objectstore")
DATA = Path("/var/lib/cdnca-objectstore")
LOGS = Path("/var/lib/cdnca-objectstore-logs")
BINARY = Path("/usr/local/lib/cdnca-runtime/rustfs")
UNIT = Path("/etc/systemd/system/cdnca-objectstore.service")
# systemd < 248 has no usable LoadCredential=/%d (247 lacks %d): the same four files are copied to a
# service-owned 0500 directory and a drop-in points RUSTFS_* at it
# (docs/install/os-support-matrix.md section 6). Newer systemd never uses these.
COMPAT_CREDENTIALS = Path("/var/lib/cdnca-objectstore-credentials")
COMPAT_DROPIN = Path(str(UNIT) + ".d") / "zz-cdnca-systemd-compat.conf"
CREDENTIAL_NAMES = ("root-access-key", "root-secret-key", "rustfs_cert.pem", "rustfs_key.pem")
# Debian/Ubuntu trust anchor; RHEL family uses /etc/pki/ca-trust (see trust_layout).
TRUST = Path("/usr/local/share/ca-certificates/cdnca-objectstore.crt")
TRUST_UPDATE = ["update-ca-certificates"]
ACCOUNT = "cdnca-objectstore"
ENDPOINT = "https://127.0.0.1:19000"
BUCKET = "cdnca-assets"
PREFIXES = ("brand-assets", "error-pages")
FRESH_PATHS = (CONFIG, DATA, LOGS, BINARY, UNIT, TRUST, COMPAT_CREDENTIALS, Path("/etc/ssl/certs/cdnca-objectstore.pem"),
               Path("/etc/pki/ca-trust/source/anchors/cdnca-objectstore.crt"),
               Path(str(UNIT) + ".d"), Path("/usr/lib/systemd/system/cdnca-objectstore.service"),
               Path("/run/systemd/system/cdnca-objectstore.service"), Path("/run/systemd/system/cdnca-objectstore.service.d"))
COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def run(args, **kwargs):
    result = subprocess.run(args, env=COMMAND_ENV, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=60, **kwargs)
    if result.returncode:
        raise ValueError("command failed: " + Path(args[0]).name)
    return result.stdout


def write_private(path, content):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@contextlib.contextmanager
def private_input(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("expected private regular single-link file")
        yield source


def read_private(path):
    with private_input(path) as source:
        data = source.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("private configuration too large")
    return data


def secure_parents(path):
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("expected absolute path")
    for parent in reversed(path.parents):
        info = parent.lstat()
        sticky_root = parent in (Path("/tmp"), Path("/run/lock")) and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 and not sticky_root:
            raise ValueError("unsafe parent directory")


def verify_archive(archive):
    parent = archive.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError("archive requires a private parent directory")
    manifest = json.loads(Path(__file__).with_name("rustfs-1.0.1.json").read_bytes())
    legacy = [{key: entry.get(key) for key in ("archive_sha256", "binary_sha256")} for entry in manifest.get("legacy_receipts", [])]
    if (manifest.get("version") != "1.0.1" or manifest.get("archive_sha256") != ARCHIVE_SHA or manifest.get("binary_sha256") != BINARY_SHA
            or legacy != list(LEGACY_RECEIPTS)):
        raise ValueError("RustFS input manifest mismatch")
    with private_input(archive) as source:
        if sha256_stream(source).hexdigest() != ARCHIVE_SHA:
            raise ValueError("RustFS archive SHA256 mismatch")
        source.seek(0)
        with zipfile.ZipFile(source) as package:
            entries = package.infolist()
            names = ARCHIVE_MEMBERS
            if len(entries) != len(names) or {entry.filename for entry in entries} != names or any(entry.is_dir() or entry.file_size > 2 * 1024**3 for entry in entries):
                raise ValueError("RustFS archive layout mismatch")
            if any(not stat.S_ISREG(entry.external_attr >> 16) for entry in entries):
                raise ValueError("RustFS archive entry is not regular")
            with package.open("rustfs") as binary:
                if sha256_stream(binary).hexdigest() != BINARY_SHA:
                    raise ValueError("RustFS binary SHA256 mismatch")


def reject_existing_state():
    for path in FRESH_PATHS:
        if os.path.lexists(path):
            raise ValueError("existing RustFS state; fresh install refused")
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup(ACCOUNT)
        except KeyError:
            continue
        raise ValueError("existing RustFS account; fresh install refused")


def sha256_stream(stream):
    """hashlib.file_digest (3.11+) with the same streaming semantics on older Python."""
    if hasattr(hashlib, "file_digest"):
        return hashlib.file_digest(stream, "sha256")
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1 << 20), b""):
        digest.update(chunk)
    return digest


def os_release():
    """platform.freedesktop_os_release (3.10+), parsed without evaluation on older Python."""
    if hasattr(platform, "freedesktop_os_release"):
        return platform.freedesktop_os_release()
    values = {}
    with open("/etc/os-release", encoding="utf-8") as source:
        for line in source:
            name, separator, value = line.strip().partition("=")
            if separator and re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                values[name] = value[1:-1] if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'" else value
    return values


# Hosts from docs/install/os-support-matrix.md. RHEL-family VERSION_ID carries
# the point release (9.4); only the major version is compared.
SUPPORTED_HOSTS = {("ubuntu", "24.04"), ("ubuntu", "22.04"), ("ubuntu", "20.04"), ("debian", "10"), ("debian", "11"), ("debian", "12"), ("debian", "13"),
                   ("rocky", "8"), ("rocky", "9"), ("rocky", "10"), ("almalinux", "8"), ("almalinux", "9"), ("almalinux", "10"),
                   ("rhel", "8"), ("rhel", "9"), ("rhel", "10")}
RHEL_FAMILY = {"rocky", "almalinux", "rhel"}


def supported_host(release):
    identity, version = release.get("ID"), release.get("VERSION_ID", "")
    if identity in RHEL_FAMILY:
        version = version.split(".", 1)[0]
    return (identity, version) in SUPPORTED_HOSTS


def native_rustfs_check(archive):
    release = os_release()
    if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() != "x86_64" or not supported_host(release):
        raise ValueError("requires root on amd64 Ubuntu 24.04/22.04/20.04, Debian 10-13 or Rocky/AlmaLinux/RHEL 8/9/10")
    for command in ("openssl", "useradd", "systemctl", TRUST_UPDATE[0]):
        if shutil.which(command, path=COMMAND_ENV["PATH"]) is None:
            raise ValueError("missing prerequisite: " + command)
    secure_parents(archive)
    verify_archive(archive)
    reject_existing_state()
    if BINARY.parent.exists() and stat.S_IMODE(BINARY.parent.lstat().st_mode) != 0o755:
        raise ValueError("existing runtime binary parent is not 0755")
    # Both families' CA paths are refused if present, but only this host's trust
    # anchor is written; RHEL's /etc/ssl/certs is a symlink into /etc/pki.
    other_trust = ("/etc/ssl/certs/", "/usr/local/share/ca-certificates/", "/etc/pki/ca-trust/")
    for path in [path for path in FRESH_PATHS if not str(path).startswith(other_trust)] + [TRUST]:
        # The shared binary parent may not exist until this fresh install.
        secure_parents(path if path.parent.exists() else path.parent)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 19000))


def create_tls(directory):
    # Restrict the newly trusted CA to loopback identities, not public domains.
    # Config-file extensions and a separate genpkey work on OpenSSL 1.0.2-3.x
    # ("-addext" needs 1.1.1+; 1.0.2 "-newkey ec" needs a parameter file).
    # OpenSSL 1.0.2 (CentOS 7) cannot evaluate IP name constraints and fails
    # every verify that meets one, so there only the DNS subtree is set; the CA
    # key stays root-only in CONFIG on every host.
    constraints = b"permitted;DNS:localhost"
    version = re.match(rb"OpenSSL ([0-9]+)\.([0-9]+)", run(["openssl", "version"]))
    if version and tuple(int(part) for part in version.groups()) >= (1, 1):
        constraints += b",permitted;IP:127.0.0.1/255.255.255.255"
    write_private(directory / "req.cnf", b"[req]\ndistinguished_name = dn\nx509_extensions = ca\n[dn]\nCN = Common Name\n[ca]\n"
                  b"subjectKeyIdentifier = hash\nbasicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign,cRLSign\n"
                  b"nameConstraints = critical," + constraints + b"\n")
    for name in ("ca.key", "rustfs_key.pem"):
        run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-pkeyopt", "ec_param_enc:named_curve", "-out", str(directory / name)])
    run(["openssl", "req", "-x509", "-new", "-batch", "-config", str(directory / "req.cnf"), "-key", str(directory / "ca.key"), "-sha256", "-days", "3650", "-set_serial", "0x" + secrets.token_hex(16), "-subj", "/CN=CDNCA objectstore local CA", "-out", str(directory / "ca.crt")])
    run(["openssl", "req", "-new", "-batch", "-config", str(directory / "req.cnf"), "-key", str(directory / "rustfs_key.pem"), "-subj", "/CN=127.0.0.1", "-out", str(directory / "server.csr")])
    write_private(directory / "server.ext", b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n")
    run(["openssl", "x509", "-req", "-in", str(directory / "server.csr"), "-CA", str(directory / "ca.crt"), "-CAkey", str(directory / "ca.key"), "-set_serial", "0x" + secrets.token_hex(16), "-days", "365", "-sha256", "-extfile", str(directory / "server.ext"), "-out", str(directory / "rustfs_cert.pem")])
    run(["openssl", "verify", "-CAfile", str(directory / "ca.crt"), "-verify_ip", "127.0.0.1", str(directory / "rustfs_cert.pem")])


def sigv4_authorization(method, path, query, headers, payload_sha256, credential, amz_date, region="us-east-1"):
    """AWS Signature Version 4 for S3 (single chunk, unsigned-path encoding once).

    Replaces curl --aws-sigv4, whose 7.76 build (RHEL 9) signs requests RustFS
    rejects with SignatureDoesNotMatch. Verified against the AWS example vector."""
    quote = lambda value: urllib.parse.quote(value, safe="-_.~")
    canonical_uri = urllib.parse.quote(urllib.parse.unquote(path), safe="/-_.~")
    pairs = sorted((quote(key), quote(value)) for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True))
    canonical_query = "&".join(key + "=" + value for key, value in pairs)
    names = sorted(name.lower() for name in headers)
    lowered = {name.lower(): " ".join(value.strip().split()) for name, value in headers.items()}
    canonical_headers = "".join(name + ":" + lowered[name] + "\n" for name in names)
    signed_headers = ";".join(names)
    canonical = "\n".join((method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_sha256))
    scope = amz_date[:8] + "/" + region + "/s3/aws4_request"
    to_sign = "\n".join(("AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()))
    key = ("AWS4" + credential[1]).encode()
    for part in (amz_date[:8], region, "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    return "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (credential[0], scope, signed_headers, signature)


def request(directory, endpoint, credential, ca, method, path, body=b"", headers=()):
    # directory is kept for the call contract; no request material touches disk.
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or parsed.hostname != "127.0.0.1" or not parsed.port or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or not path.startswith("/") or "\r" in path or "\n" in path:
        raise ValueError("requires loopback HTTPS origin")
    if any(not value or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in value) for value in credential):
        raise ValueError("invalid private credential encoding")
    target_path, _, query = path.partition("?")
    payload = hashlib.sha256(body).hexdigest()
    signed = {"Host": "127.0.0.1:%d" % parsed.port, "Content-Type": "application/json", "x-amz-content-sha256": payload,
              "x-amz-date": datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")}
    for header in headers:
        name, separator, value = header.partition(":")
        if not separator or not name.strip() or any(c in header for c in "\r\n"):
            raise ValueError("invalid request header")
        signed[name.strip()] = value.strip()
    authorization = sigv4_authorization(method, target_path, query, signed, payload, credential, signed["x-amz-date"])
    # Never consult proxy settings; trust only the private CA or the system store.
    context = ssl.create_default_context(cafile=str(ca)) if ca is not None else ssl.create_default_context()
    connection = http.client.HTTPSConnection("127.0.0.1", parsed.port, timeout=10, context=context)
    try:
        connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for name, value in signed.items():
            connection.putheader(name, value)
        connection.putheader("Authorization", authorization)
        connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        response = connection.getresponse()
        content = response.read(4 * 1024 * 1024 + 1)
        if len(content) > 4 * 1024 * 1024:
            raise ValueError("RustFS response too large")
        return response.status, {key.lower(): value.strip() for key, value in response.getheaders()}, content
    except (OSError, http.client.HTTPException) as error:
        raise ValueError("RustFS request failed") from error
    finally:
        connection.close()


def iam_policy(prefix):
    if prefix not in PREFIXES:
        raise ValueError("unknown object prefix")
    bucket = "arn:aws:s3:::" + BUCKET
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetBucketVersioning"], "Resource": [bucket]},
        {"Effect": "Allow", "Action": ["s3:ListBucketVersions"], "Resource": [bucket], "Condition": {"StringLike": {"s3:prefix": [prefix + "/*"]}}},
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"], "Resource": [bucket + "/" + prefix + "/*"]},
    ]}


def provision_iam(directory, endpoint):
    credential = tuple(read_private(directory / name).decode() for name in ("root-access-key", "root-secret-key"))
    ca = directory / "ca.crt"
    calls = [("/" + BUCKET, b""), ("/" + BUCKET + "?versioning", b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>')]
    runtime = {"endpoint": endpoint, "region": "us-east-1", "bucket": BUCKET, "users": {}}
    for prefix in PREFIXES:
        access, secret = "cdnca-" + prefix, secrets.token_hex(32)
        runtime["users"][prefix] = {"access_key": access, "secret_key": secret, "prefix": prefix}
        query = urllib.parse.urlencode
        calls += [
            ("/rustfs/admin/v3/add-user?" + query({"accessKey": access}), json.dumps({"secretKey": secret, "status": "enabled"}).encode()),
            ("/rustfs/admin/v3/add-canned-policy?" + query({"name": access}), json.dumps(iam_policy(prefix)).encode()),
            ("/rustfs/admin/v3/set-user-or-group-policy?" + query({"policyName": access, "userOrGroup": access, "isGroup": "false"}), b""),
        ]
    # Persist before the first IAM mutation; failure must not silently rotate keys.
    write_private(directory / "runtime.json", json.dumps(runtime).encode())
    for path, body in calls:
        if request(directory, endpoint, credential, ca, "PUT", path, body)[0] != 200:
            raise ValueError("RustFS native provisioning rejected")


def probe_runtime(directory, system_trust=False):
    runtime = json.loads(read_private(directory / "runtime.json"))
    endpoint = runtime["endpoint"]
    ca = None if system_trust else directory / "ca.crt"
    body = b"cdnca-native-objectstore-preflight-v1"
    for prefix in PREFIXES:
        user = runtime["users"][prefix]
        credential = (user["access_key"], user["secret_key"])
        call = lambda method, path, data=b"", headers=(): request(directory, endpoint, credential, ca, method, path, data, headers)
        status, _, versioning = call("GET", "/" + BUCKET + "?versioning")
        # "{*}" namespace wildcards need Python 3.8+; match the local name instead.
        if status != 200 or [element.text for element in ET.fromstring(versioning).iter()
                             if element.tag.rsplit("}", 1)[-1] == "Status"] != ["Enabled"]:
            raise ValueError("bucket versioning unavailable")
        key = prefix + "/native-preflight/" + secrets.token_hex(16)
        path = "/" + BUCKET + "/" + key
        status, headers, _ = call("PUT", path, body, ("If-None-Match: *",))
        version, etag = headers.get("x-amz-version-id"), headers.get("etag")
        if status != 200 or not version or version == "null" or not etag or etag.startswith("W/"):
            raise ValueError("versioned immutable write failed")
        bound = path + "?" + urllib.parse.urlencode({"versionId": version})
        try:
            status, _, opened = call("GET", bound, headers=("If-Match: " + etag,))
            if status != 200 or opened != body or call("PUT", path, b"different", ("If-None-Match: *",))[0] != 412:
                raise ValueError("immutable object contract failed")
            other = PREFIXES[1] if prefix == PREFIXES[0] else PREFIXES[0]
            versioning_body = b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>'
            denied = [("GET", "/" + BUCKET + "/" + other + "/native-preflight/" + secrets.token_hex(16), b""), ("PUT", "/" + BUCKET + "?versioning", versioning_body), ("GET", "/rustfs/admin/v3/list-users", b"")]
            if any(call(method, target, data)[0] != 403 for method, target, data in denied):
                raise ValueError("runtime identity has excessive privileges")
            wrong = (credential[0], credential[1] + "wrong")
            if request(directory, endpoint, wrong, ca, "GET", bound)[0] != 403:
                raise ValueError("wrong credential was accepted")
        finally:
            if call("DELETE", bound)[0] != 204:
                raise ValueError("preflight exact-version cleanup failed")
        status, _, listed = call("GET", "/" + BUCKET + "?" + urllib.parse.urlencode({"versions": "", "prefix": key}))
        if status != 200 or any(element.tag.rsplit("}", 1)[-1] in ("Version", "DeleteMarker") for element in ET.fromstring(listed)):
            raise ValueError("preflight version cleanup not proven")


def systemd_knows(directive):
    """Same probe as scripts/lib/systemd-compat.sh: the gperf directive table."""
    for name in ("/lib/systemd/systemd", "/usr/lib/systemd/systemd"):
        try:
            with open(name, "rb") as binary:
                if (b"\0" + directive.encode() + b"\0") in binary.read():
                    return True
        except OSError:
            continue
    for directory in ("/lib/systemd", "/usr/lib/systemd", "/usr/lib64/systemd", "/usr/lib/x86_64-linux-gnu/systemd", "/lib/x86_64-linux-gnu/systemd"):
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            if name.startswith("libsystemd-") and name.endswith(".so"):
                with open(os.path.join(directory, name), "rb") as library:
                    if (b"\0" + directive.encode() + b"\0") in library.read():
                        return True
    return False


def systemd_credentials_usable():
    """LoadCredential= arrived in 247 but the %d specifier only in 248: on 247
    (Debian 11) the Environment=...%d lines are dropped and RustFS has no keys."""
    if not systemd_knows("Service.LoadCredential"):
        return False
    match = re.match(rb"systemd ([0-9]+)\b", run(["systemctl", "--version"]))
    return bool(match) and int(match.group(1)) >= 248


def compat_dropin():
    return ("[Service]\n"
            "Environment=RUSTFS_ACCESS_KEY_FILE=" + str(COMPAT_CREDENTIALS / "root-access-key") + "\n"
            "Environment=RUSTFS_SECRET_KEY_FILE=" + str(COMPAT_CREDENTIALS / "root-secret-key") + "\n"
            "Environment=RUSTFS_TLS_PATH=" + str(COMPAT_CREDENTIALS) + "\n")


def install_compat_credentials(account):
    COMPAT_CREDENTIALS.mkdir(mode=0o700)
    os.chown(COMPAT_CREDENTIALS, account.pw_uid, account.pw_gid)
    for name in CREDENTIAL_NAMES:
        write_private(COMPAT_CREDENTIALS / name, read_private(CONFIG / name))
        os.chown(COMPAT_CREDENTIALS / name, account.pw_uid, account.pw_gid)
        os.chmod(COMPAT_CREDENTIALS / name, 0o400)
    os.chmod(COMPAT_CREDENTIALS, 0o500)
    COMPAT_DROPIN.parent.mkdir(mode=0o755)
    os.chmod(COMPAT_DROPIN.parent, 0o755)
    write_private(COMPAT_DROPIN, compat_dropin().encode())
    os.chmod(COMPAT_DROPIN, 0o644)


def verify_compat_credentials():
    """With the compat drop-in, its copies must equal the root-only originals."""
    if not os.path.lexists(COMPAT_DROPIN):
        if not systemd_credentials_usable():
            raise ValueError("systemd lacks usable LoadCredential and no compatibility credentials exist")
        return
    account = pwd.getpwnam(ACCOUNT)
    if COMPAT_DROPIN.read_text() != compat_dropin():
        raise ValueError("compatibility drop-in mismatch")
    info = COMPAT_CREDENTIALS.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != account.pw_uid or stat.S_IMODE(info.st_mode) != 0o500:
        raise ValueError("unsafe compatibility credential directory")
    if set(os.listdir(COMPAT_CREDENTIALS)) != set(CREDENTIAL_NAMES):
        raise ValueError("compatibility credential inventory mismatch")
    for name in CREDENTIAL_NAMES:
        copy = (COMPAT_CREDENTIALS / name).lstat()
        if (not stat.S_ISREG(copy.st_mode) or copy.st_nlink != 1 or copy.st_uid != account.pw_uid or stat.S_IMODE(copy.st_mode) != 0o400
                or (COMPAT_CREDENTIALS / name).read_bytes() != read_private(CONFIG / name)):
            raise ValueError("compatibility credential mismatch")


def service_unit():
    credentials = "\n".join("LoadCredential=" + name + ":" + str(CONFIG / name) for name in CREDENTIAL_NAMES)
    return f"""[Unit]
Description=CDNCA local versioned object store
After=network.target
[Service]
Type=simple
User={ACCOUNT}
Group={ACCOUNT}
WorkingDirectory={DATA}
{credentials}
Environment=RUSTFS_ACCESS_KEY_FILE=%d/root-access-key
Environment=RUSTFS_SECRET_KEY_FILE=%d/root-secret-key
Environment=RUSTFS_TLS_PATH=%d
Environment=RUSTFS_ADDRESS=127.0.0.1:19000
Environment=RUSTFS_REGION=us-east-1
Environment=RUSTFS_CONSOLE_ENABLE=false
Environment=RUSTFS_CONSOLE_ADDRESS=127.0.0.1:0
Environment=RUSTFS_CHECK_UPDATE=false
Environment=RUSTFS_OBS_ENDPOINT=
Environment=RUSTFS_OBS_TRACES_EXPORT_ENABLED=false
Environment=RUSTFS_OBS_METRICS_EXPORT_ENABLED=false
Environment=RUSTFS_OBS_LOGS_EXPORT_ENABLED=false
Environment=RUSTFS_OBS_PROFILING_EXPORT_ENABLED=false
Environment=RUSTFS_OBS_LOG_STDOUT_ENABLED=false
Environment=RUSTFS_OBS_LOGGER_LEVEL=off
Environment=RUSTFS_OBS_LOG_DIRECTORY={LOGS}
Environment=RUSTFS_RUNTIME_DIAL9_ENABLED=false
ExecStart={BINARY} server {DATA}
Restart=on-failure
RestartSec=3
TimeoutStopSec=30
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={DATA} {LOGS}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
"""


def accepted_receipts():
    variants = ({"archive_sha256": ARCHIVE_SHA, "binary_sha256": BINARY_SHA},) + tuple(LEGACY_RECEIPTS)
    return [{"schema": "cdnca.native-rustfs/v1", "version": "1.0.1", **variant, "endpoint": ENDPOINT} for variant in variants]


def verify_installed(archive):
    secure_parents(archive)
    verify_archive(archive)
    receipt = json.loads(read_private(CONFIG / "installed.json"))
    if receipt not in accepted_receipts():
        raise ValueError("installed receipt mismatch")
    directory = CONFIG.lstat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or stat.S_IMODE(directory.st_mode) != 0o700:
        raise ValueError("unsafe private runtime directory")
    runtime = json.loads(read_private(CONFIG / "runtime.json"))
    if set(runtime) != {"endpoint", "region", "bucket", "users"} or runtime["endpoint"] != ENDPOINT or runtime["region"] != "us-east-1" or runtime["bucket"] != BUCKET or set(runtime["users"]) != set(PREFIXES):
        raise ValueError("runtime configuration mismatch")
    for prefix, user in runtime["users"].items():
        if set(user) != {"access_key", "secret_key", "prefix"} or user["access_key"] != "cdnca-" + prefix or user["prefix"] != prefix or len(user["secret_key"]) != 64 or any(c not in "0123456789abcdef" for c in user["secret_key"]):
            raise ValueError("runtime identity mismatch")
    for name in ("root-access-key", "root-secret-key", "ca.key", "rustfs_key.pem", "rustfs_cert.pem"):
        read_private(CONFIG / name)
    for path in (BINARY, UNIT, TRUST):
        secure_parents(path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ValueError("unsafe installed public file")
    # The installed binary must be the build its own receipt names.
    with BINARY.open("rb") as binary:
        if sha256_stream(binary).hexdigest() != receipt["binary_sha256"]:
            raise ValueError("installed binary mismatch")
    if UNIT.read_text() != service_unit() or TRUST.read_bytes() != read_private(CONFIG / "ca.crt"):
        raise ValueError("installed unit or CA mismatch")
    verify_compat_credentials()
    run(["systemctl", "is-active", "--quiet", UNIT.name])
    run(["systemctl", "is-enabled", "--quiet", UNIT.name])


def native_rustfs_preflight(archive):
    verify_installed(archive)
    probe_runtime(CONFIG, system_trust=True)


def native_rustfs_install(archive):
    native_rustfs_check(archive)
    trusted = False
    try:
        CONFIG.mkdir(mode=0o700)
        write_private(CONFIG / "root-access-key", ("cdnca-root-" + secrets.token_hex(12)).encode())
        write_private(CONFIG / "root-secret-key", secrets.token_hex(32).encode())
        create_tls(CONFIG)
        run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", str(DATA), "--shell", "/usr/sbin/nologin", ACCOUNT])
        account = pwd.getpwnam(ACCOUNT)
        for path in (DATA, LOGS):
            path.mkdir(mode=0o700)
            os.chown(path, account.pw_uid, account.pw_gid)
        if not BINARY.parent.exists():
            BINARY.parent.mkdir(mode=0o755)
            os.chmod(BINARY.parent, 0o755)
        with private_input(archive) as source, zipfile.ZipFile(source) as package, package.open("rustfs") as binary:
            with os.fdopen(os.open(BINARY, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755), "wb") as output:
                shutil.copyfileobj(binary, output)
                output.flush()
                os.fsync(output.fileno())
        os.chmod(BINARY, 0o755)
        with BINARY.open("rb") as binary:
            if sha256_stream(binary).hexdigest() != BINARY_SHA:
                raise ValueError("extracted binary mismatch; refusing execution")
        if run([str(BINARY), "-V"]).strip() != b"rustfs 1.0.1":
            raise ValueError("installed executable version mismatch")
        write_private(UNIT, service_unit().encode())
        os.chmod(UNIT, 0o644)
        if not systemd_credentials_usable():
            install_compat_credentials(account)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "--now", UNIT.name])
        credential = tuple(read_private(CONFIG / name).decode() for name in ("root-access-key", "root-secret-key"))
        deadline = time.monotonic() + 45
        while True:
            try:
                if request(CONFIG, ENDPOINT, credential, CONFIG / "ca.crt", "GET", "/")[0] == 200:
                    break
            except ValueError:
                pass
            if time.monotonic() >= deadline:
                raise ValueError("RustFS TLS readiness deadline exceeded")
            time.sleep(0.2)
        provision_iam(CONFIG, ENDPOINT)
        probe_runtime(CONFIG)
        write_private(TRUST, read_private(CONFIG / "ca.crt"))
        os.chmod(TRUST, 0o644)
        trusted = True
        run(TRUST_UPDATE)
        probe_runtime(CONFIG, system_trust=True)
        write_private(CONFIG / "installed.json", json.dumps({"schema": "cdnca.native-rustfs/v1", "version": "1.0.1", "archive_sha256": ARCHIVE_SHA, "binary_sha256": BINARY_SHA, "endpoint": ENDPOINT}).encode())
        native_rustfs_preflight(archive)
    except Exception:
        # Preserve state/credentials; never reinitialize an ambiguous failed install.
        if UNIT.exists() and UNIT.is_file() and UNIT.read_text() == service_unit():
            with contextlib.suppress(Exception):
                run(["systemctl", "disable", "--now", UNIT.name])
        if trusted and TRUST.is_file() and TRUST.read_bytes() == read_private(CONFIG / "ca.crt"):
            TRUST.unlink()
            run(TRUST_UPDATE)
        raise


def trust_layout(release):
    """Select the system CA anchor directory and its update command."""
    global TRUST, TRUST_UPDATE
    if release.get("ID") in RHEL_FAMILY:
        TRUST = Path("/etc/pki/ca-trust/source/anchors/cdnca-objectstore.crt")
        TRUST_UPDATE = ["update-ca-trust", "extract"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "install", "preflight"))
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0:
        raise ValueError("root required")
    trust_layout(os_release())
    if args.action == "install":
        secure_parents(Path("/run/lock/cdnca-objectstore-install.lock"))
        with os.fdopen(os.open("/run/lock/cdnca-objectstore-install.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), "r+b") as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError("unsafe installation lock")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            native_rustfs_install(args.archive)
    else:
        {"check": native_rustfs_check, "preflight": native_rustfs_preflight}[args.action](args.archive)
    print(json.dumps({"status": "passed", "action": args.action, "version": "1.0.1", "runtime_config": str(CONFIG / "runtime.json"), "receipt": str(CONFIG / "installed.json")}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile, ET.ParseError):
        # Never print command output, HTTP bodies, configuration or credentials.
        print("native RustFS operation failed; existing state preserved", file=sys.stderr)
        sys.exit(1)
