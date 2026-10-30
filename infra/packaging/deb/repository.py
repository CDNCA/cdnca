#!/usr/bin/env python3
"""Deterministic Debian package and signed apt repository tooling for OPS-11."""

from __future__ import annotations

import argparse
import email.utils
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
SUITE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
ARCH_MACHINE = {"amd64": 62, "arm64": 183}
MANIFEST_KEYS = (
    "manifest_version", "release_sequence", "version", "artifact_path", "artifact_sha256",
    "artifact_size", "sbom_path", "sbom_sha256", "sbom_size", "os", "arch",
    "source_repository", "source_commit", "build_time", "minimum_control_protocol",
    "minimum_agent_protocol",
)


class PackagingError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def fail(code: str, message: str) -> None:
    raise PackagingError(code, message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def clean_absolute(value: str, *, directory: bool = False, existing: bool = True) -> Path:
    if not value.startswith("/") or any(part in ("", ".", "..") for part in value.split("/")[1:]):
        fail("PKG_PATH_INVALID", f"path must be clean and absolute: {value}")
    path = Path(value)
    if existing:
        try:
            info = path.lstat()
        except OSError as error:
            fail("PKG_PATH_INVALID", f"path is unavailable: {path}: {error}")
        expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not expected or stat.S_ISLNK(info.st_mode) or (not directory and info.st_nlink != 1):
            fail("PKG_PATH_INVALID", f"path type is unsafe: {path}")
    return path


def uint(value: str, name: str, minimum: int = 1) -> int:
    if not re.fullmatch(r"[1-9][0-9]*", value):
        fail("PKG_INPUT_INVALID", f"{name} must be a canonical positive integer")
    result = int(value)
    if result < minimum or result > 2**63 - 1:
        fail("PKG_INPUT_INVALID", f"{name} is outside the supported range")
    return result


def parse_manifest(path: Path) -> dict[str, str]:
    encoded = path.read_bytes()
    if not encoded.endswith(b"\n") or b"\r" in encoded or len(encoded) > 16384:
        fail("PKG_MANIFEST_INVALID", "manifest encoding is not canonical")
    try:
        lines = encoded.decode("ascii").splitlines()
    except UnicodeDecodeError:
        fail("PKG_MANIFEST_INVALID", "manifest must be ASCII")
    if len(lines) != len(MANIFEST_KEYS):
        fail("PKG_MANIFEST_INVALID", "manifest field count differs from v2")
    result: dict[str, str] = {}
    for expected, line in zip(MANIFEST_KEYS, lines, strict=True):
        key, separator, value = line.partition("=")
        if separator != "=" or key != expected or not value:
            fail("PKG_MANIFEST_INVALID", f"manifest field {expected} is invalid")
        result[key] = value
    return result


def run(command: list[str], *, output: Path | None = None) -> bytes:
    try:
        completed = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        fail("PKG_COMMAND_FAILED", f"cannot execute {command[0]}: {error}")
    if completed.returncode != 0:
        fail("PKG_COMMAND_FAILED", f"{command[0]} failed: {completed.stderr.decode(errors='replace').strip()}")
    if output is not None:
        output.write_bytes(completed.stdout)
    return completed.stdout


def verify_release_inputs(args: argparse.Namespace) -> tuple[dict[str, str], Path, Path, Path, Path, Path]:
    artifact = clean_absolute(args.artifact)
    sbom = clean_absolute(args.sbom)
    manifest_path = clean_absolute(args.manifest)
    signature = clean_absolute(args.manifest_signature)
    public_key = clean_absolute(args.release_public_key)
    manifest = parse_manifest(manifest_path)
    if args.architecture not in ARCH_MACHINE or manifest["arch"] != args.architecture:
        fail("PKG_ARCH_INVALID", "package and manifest architectures differ")
    if not SEMVER.fullmatch(args.version) or manifest["version"] != args.version:
        fail("PKG_VERSION_INVALID", "package and manifest versions differ")
    sequence = uint(args.release_sequence, "release sequence")
    if manifest["release_sequence"] != str(sequence):
        fail("PKG_MANIFEST_INVALID", "release sequence differs from manifest")
    if manifest["manifest_version"] != "2" or manifest["os"] != "linux":
        fail("PKG_MANIFEST_INVALID", "manifest schema or operating system is unsupported")
    if manifest["artifact_path"] != "edge-agent" or manifest["sbom_path"] != "edge-agent.spdx.json":
        fail("PKG_MANIFEST_INVALID", "manifest paths are unsupported")
    if sha256_file(artifact) != manifest["artifact_sha256"] or artifact.stat().st_size != int(manifest["artifact_size"]):
        fail("PKG_ARTIFACT_INVALID", "artifact digest or size differs from manifest")
    if sha256_file(sbom) != manifest["sbom_sha256"] or sbom.stat().st_size != int(manifest["sbom_size"]):
        fail("PKG_SBOM_INVALID", "SBOM digest or size differs from manifest")
    with artifact.open("rb") as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack("<H", header[18:20])[0] != ARCH_MACHINE[args.architecture]:
        fail("PKG_ARCH_INVALID", "artifact ELF architecture differs from package")
    run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key), "-rawin",
         "-in", str(manifest_path), "-sigfile", str(signature)])
    return manifest, artifact, sbom, manifest_path, signature, public_key


def debian_version(version: str) -> str:
    core, separator, suffix = version.partition("-")
    return f"{core}{'~' + suffix if separator else ''}-1"


def add_parent_directories(entries: dict[str, tuple[bytes, int]], name: str, epoch: int) -> None:
    del epoch
    parts = name.split("/")[:-1]
    for index in range(1, len(parts) + 1):
        directory = "/".join(parts[:index]) + "/"
        entries.setdefault(directory, (b"", 0o755))


def tar_gzip(entries: dict[str, tuple[bytes, int]], epoch: int) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name in sorted(entries):
            content, mode = entries[name]
            info = tarfile.TarInfo(name)
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = epoch
            info.mode = mode
            if name.endswith("/"):
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            else:
                info.type = tarfile.REGTYPE
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=epoch) as stream:
        stream.write(raw.getvalue())
    return compressed.getvalue()


def write_ar(path: Path, members: list[tuple[str, bytes]], epoch: int) -> None:
    with path.open("xb") as stream:
        stream.write(b"!<arch>\n")
        for name, content in members:
            encoded_name = (name + "/").encode("ascii")
            if len(encoded_name) > 16:
                fail("PKG_BUILD_INVALID", f"ar member name is too long: {name}")
            header = (
                encoded_name.ljust(16) + str(epoch).encode().ljust(12) + b"0     " + b"0     " +
                b"100644  " + str(len(content)).encode().ljust(10) + b"`\n"
            )
            if len(header) != 60:
                fail("PKG_BUILD_INVALID", "internal ar header length mismatch")
            stream.write(header)
            stream.write(content)
            if len(content) % 2:
                stream.write(b"\n")
    os.chmod(path, 0o444)


def read_asset_tree(root: Path, relative: str, destination: str, entries: dict[str, tuple[bytes, int]]) -> None:
    source_root = root / relative
    info = source_root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        fail("PKG_ASSET_INVALID", f"asset directory is unsafe: {source_root}")
    for source in sorted(source_root.rglob("*")):
        relative_path = source.relative_to(source_root).as_posix()
        target = f"{destination}/{relative_path}"
        source_info = source.lstat()
        if stat.S_ISDIR(source_info.st_mode):
            entries[target + "/"] = (b"", 0o755)
        elif stat.S_ISREG(source_info.st_mode) and source_info.st_nlink == 1:
            mode = 0o555 if relative == "scripts" else 0o644
            entries[target] = (source.read_bytes(), mode)
            add_parent_directories(entries, target, 0)
        else:
            fail("PKG_ASSET_INVALID", f"asset type is unsafe: {source}")


def render_maintainer(path: Path, substitutions: dict[str, str]) -> bytes:
    source = path.read_text(encoding="utf-8")
    for key, value in substitutions.items():
        source = source.replace(f"@{key}@", value)
    if re.search(r"@[A-Z_]+@", source):
        fail("PKG_BUILD_INVALID", f"unresolved maintainer placeholder in {path.name}")
    return source.encode()


def command_build_package(args: argparse.Namespace) -> None:
    manifest, artifact, sbom, manifest_path, signature, public_key = verify_release_inputs(args)
    epoch = uint(args.source_date_epoch, "source date epoch", 100_000_000)
    key_version = uint(args.rollback_key_version, "rollback key version")
    assets = clean_absolute(args.assets, directory=True)
    maintainer = clean_absolute(args.maintainer, directory=True)
    output = clean_absolute(args.output_dir, directory=True)
    version = args.version
    deb_version = debian_version(version)
    package_path = output / f"cdnca-edge-agent_{deb_version}_{args.architecture}.deb"
    if package_path.exists() or package_path.is_symlink():
        fail("PKG_OUTPUT_EXISTS", f"package output already exists: {package_path}")

    data: dict[str, tuple[bytes, int]] = {}
    bundle = f"usr/lib/cdnca-edge-agent/deb-bundles/{version}"
    for name, source, mode in (
        ("edge-agent", artifact, 0o555), ("edge-agent.spdx.json", sbom, 0o444),
        ("manifest", manifest_path, 0o444), ("manifest.sig", signature, 0o444),
        ("release-signing.pem", public_key, 0o444),
    ):
        target = f"{bundle}/{name}"
        data[target] = (source.read_bytes(), mode)
        add_parent_directories(data, target, epoch)
    trust_target = f"usr/share/cdnca-edge-agent/trust/rollback-authority-v{key_version}.pem"
    data[trust_target] = (public_key.read_bytes(), 0o444)
    add_parent_directories(data, trust_target, epoch)

    read_asset_tree(assets, "scripts", "usr/libexec/cdnca-edge-agent", data)
    for relative in ("systemd", "sysusers", "tmpfiles", "logrotate", "config"):
        read_asset_tree(assets, relative, f"usr/libexec/cdnca-edge-agent/assets/{relative}", data)
    readme = assets / "README.md"
    if not readme.is_file() or readme.is_symlink():
        fail("PKG_ASSET_INVALID", "packaging README is unavailable")
    data["usr/libexec/cdnca-edge-agent/assets/README.md"] = (readme.read_bytes(), 0o644)
    data["usr/share/doc/cdnca-edge-agent/README.md"] = (readme.read_bytes(), 0o644)
    add_parent_directories(data, "usr/libexec/cdnca-edge-agent/assets/README.md", epoch)
    add_parent_directories(data, "usr/share/doc/cdnca-edge-agent/README.md", epoch)

    fixed_assets = (
        ("systemd/cdnca-edge-agent.service", "usr/lib/systemd/system/cdnca-edge-agent.service", 0o644),
        ("sysusers/cdnca-edge-agent.conf", "usr/lib/sysusers.d/cdnca-edge-agent.conf", 0o644),
        ("tmpfiles/cdnca-edge-agent.conf", "usr/lib/tmpfiles.d/cdnca-edge-agent.conf", 0o644),
        ("logrotate/cdnca-edge-agent", "etc/logrotate.d/cdnca-edge-agent", 0o644),
        ("config/agent.env", "etc/cdnca-edge-agent/agent.env", 0o600),
        ("config/config.example.json", "usr/share/doc/cdnca-edge-agent/config.example.json", 0o644),
    )
    for source_name, target, mode in fixed_assets:
        source = assets / source_name
        data[target] = (source.read_bytes(), mode)
        add_parent_directories(data, target, epoch)

    installed_size = (sum(len(content) for name, (content, _) in data.items() if not name.endswith("/")) + 1023) // 1024
    control_text = (
        f"Package: cdnca-edge-agent\nVersion: {deb_version}\nSection: net\nPriority: optional\n"
        f"Architecture: {args.architecture}\nMaintainer: CDNCA Release Engineering <release@cdnca.invalid>\n"
        f"Installed-Size: {installed_size}\nDepends: openssl, jq, perl, util-linux, systemd (>= 252), systemd-sysv, logrotate\n"
        "Description: CDNCA edge control agent\n Signed immutable release bundle and atomic systemd lifecycle for CDNCA edge nodes.\n"
    )
    substitutions = {
        "VERSION": version,
        "DEBIAN_VERSION": deb_version,
        "RELEASE_SEQUENCE": manifest["release_sequence"],
        "ROLLBACK_KEY_VERSION": str(key_version),
    }
    control: dict[str, tuple[bytes, int]] = {"control": (control_text.encode(), 0o644)}
    for script_name in ("preinst", "postinst", "prerm", "postrm"):
        source = maintainer / script_name
        if not source.is_file() or source.is_symlink():
            fail("PKG_ASSET_INVALID", f"maintainer script is unavailable: {script_name}")
        control[script_name] = (render_maintainer(source, substitutions), 0o755)
    control["conffiles"] = (b"/etc/cdnca-edge-agent/agent.env\n", 0o644)
    md5_lines = []
    for name in sorted(data):
        if not name.endswith("/"):
            md5_lines.append(f"{hashlib.md5(data[name][0], usedforsecurity=False).hexdigest()}  {name}")
    control["md5sums"] = (("\n".join(md5_lines) + "\n").encode(), 0o644)

    write_ar(package_path, [
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", tar_gzip(control, epoch)),
        ("data.tar.gz", tar_gzip(data, epoch)),
    ], epoch)
    print(package_path)


def read_ar(path: Path) -> dict[str, bytes]:
    encoded = path.read_bytes()
    if not encoded.startswith(b"!<arch>\n"):
        fail("PKG_DEB_INVALID", "package lacks ar magic")
    offset = 8
    members: dict[str, bytes] = {}
    while offset < len(encoded):
        if offset + 60 > len(encoded):
            fail("PKG_DEB_INVALID", "truncated ar header")
        header = encoded[offset:offset + 60]
        if header[58:60] != b"`\n":
            fail("PKG_DEB_INVALID", "invalid ar header")
        name = header[:16].decode("ascii").strip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            fail("PKG_DEB_INVALID", "invalid ar member size")
        offset += 60
        members[name] = encoded[offset:offset + size]
        offset += size + (size % 2)
    if set(members) != {"debian-binary", "control.tar.gz", "data.tar.gz"} or members["debian-binary"] != b"2.0\n":
        fail("PKG_DEB_INVALID", "unexpected Debian archive members")
    return members


def read_tar(encoded: bytes) -> dict[str, tuple[bytes, int]]:
    result: dict[str, tuple[bytes, int]] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(encoded), mode="r:gz") as archive:
            for member in archive.getmembers():
                name = member.name.lstrip("./")
                if not name or member.isdir():
                    continue
                if not member.isfile() or member.issym() or member.islnk() or name.startswith("/") or ".." in Path(name).parts:
                    fail("PKG_DEB_INVALID", f"unsafe tar member {member.name}")
                stream = archive.extractfile(member)
                if stream is None:
                    fail("PKG_DEB_INVALID", f"cannot read tar member {member.name}")
                result[name] = (stream.read(), member.mode)
    except tarfile.TarError as error:
        fail("PKG_DEB_INVALID", f"cannot parse package tar: {error}")
    return result


def parse_control(encoded: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    current = ""
    for line in encoded.decode("utf-8").splitlines():
        if line.startswith(" ") and current:
            fields[current] += "\n" + line
            continue
        key, separator, value = line.partition(": ")
        if separator != ": " or key in fields:
            fail("PKG_DEB_INVALID", "invalid or duplicate control field")
        fields[key] = value
        current = key
    for required in ("Package", "Version", "Architecture", "Depends", "Description"):
        if required not in fields:
            fail("PKG_DEB_INVALID", f"missing control field {required}")
    return fields


def inspect_deb(path: Path) -> tuple[dict[str, str], dict[str, tuple[bytes, int]], dict[str, tuple[bytes, int]]]:
    members = read_ar(path)
    control = read_tar(members["control.tar.gz"])
    data = read_tar(members["data.tar.gz"])
    if "control" not in control:
        fail("PKG_DEB_INVALID", "control archive lacks control file")
    fields = parse_control(control["control"][0])
    for name, (content, _) in {**control, **data}.items():
        if b"PRIVATE KEY" in content:
            fail("PKG_PRIVATE_KEY_FOUND", f"private key marker found in {name}")
    return fields, control, data


def command_inspect_package(args: argparse.Namespace) -> None:
    package = clean_absolute(args.package)
    fields, control, data = inspect_deb(package)
    if fields["Package"] != "cdnca-edge-agent" or fields["Architecture"] != args.expect_architecture or fields["Version"] != args.expect_version:
        fail("PKG_DEB_INVALID", "package identity differs from expectation")
    for lifecycle in args.require_lifecycle.split(","):
        if lifecycle not in control or control[lifecycle][1] & 0o111 == 0:
            fail("PKG_DEB_INVALID", f"missing executable lifecycle script {lifecycle}")
    for required in args.require_path:
        if required not in data:
            fail("PKG_DEB_INVALID", f"missing required payload {required}")
    print(f"reason_code=PKG_PACKAGE_VERIFIED path={package}")


def deterministic_gzip(encoded: bytes, epoch: int) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, compresslevel=9, mtime=epoch) as stream:
        stream.write(encoded)
    return output.getvalue()


def format_release_date(epoch: int) -> str:
    return email.utils.formatdate(epoch, usegmt=True)


def command_publish(args: argparse.Namespace) -> None:
    packages_dir = clean_absolute(args.packages_dir, directory=True)
    output = clean_absolute(args.output_dir, existing=False)
    if output.exists() or output.is_symlink():
        fail("APT_OUTPUT_EXISTS", f"repository output already exists: {output}")
    if not SUITE.fullmatch(args.suite) or not SUITE.fullmatch(args.component):
        fail("APT_INPUT_INVALID", "suite or component is invalid")
    epoch = uint(args.source_date_epoch, "source date epoch", 100_000_000)
    valid_until = uint(args.valid_until_epoch, "valid until epoch", epoch + 1)
    if valid_until - epoch > 2_678_400:
        fail("APT_INPUT_INVALID", "repository validity exceeds 31 days")
    fingerprint = args.fingerprint.upper()
    if not FINGERPRINT.fullmatch(fingerprint):
        fail("APT_KEY_INVALID", "signing fingerprint must be a full fingerprint")
    key_version = uint(args.key_version, "key version")
    gpg_home = clean_absolute(args.gpg_home, directory=True)
    policy_output = clean_absolute(args.policy_output, existing=False)
    if policy_output.exists() or policy_output.is_symlink():
        fail("APT_OUTPUT_EXISTS", f"policy output already exists: {policy_output}")
    package_files = sorted(packages_dir.glob("*.deb"))
    if not package_files:
        fail("APT_INPUT_INVALID", "no Debian packages were supplied")

    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".cdnca-edge-apt.", dir=parent))
    try:
        pool = work / "pool" / args.component / "c" / "cdnca-edge-agent"
        pool.mkdir(parents=True)
        package_rows: list[tuple[Path, dict[str, str], str]] = []
        for source in package_files:
            if source.is_symlink() or source.stat().st_nlink != 1:
                fail("APT_INPUT_INVALID", f"unsafe package input: {source}")
            fields, _, _ = inspect_deb(source)
            if fields["Package"] != "cdnca-edge-agent" or fields["Architecture"] not in ARCH_MACHINE:
                fail("APT_INPUT_INVALID", f"unexpected package identity: {source}")
            destination = pool / source.name
            shutil.copyfile(source, destination)
            os.chmod(destination, 0o444)
            package_rows.append((destination, fields, destination.relative_to(work).as_posix()))

        architectures = sorted({fields["Architecture"] for _, fields, _ in package_rows})
        for architecture in architectures:
            binary = work / "dists" / args.suite / args.component / f"binary-{architecture}"
            binary.mkdir(parents=True)
            paragraphs = []
            for package, fields, relative in sorted(package_rows, key=lambda item: (item[1]["Version"], item[2])):
                if fields["Architecture"] != architecture:
                    continue
                paragraphs.append(
                    f"Package: {fields['Package']}\nVersion: {fields['Version']}\nArchitecture: {architecture}\n"
                    f"Maintainer: {fields.get('Maintainer', '')}\nDepends: {fields['Depends']}\nDescription: {fields['Description']}\n"
                    f"Filename: {relative}\nSize: {package.stat().st_size}\nSHA256: {sha256_file(package)}\n"
                )
            packages_encoded = ("\n".join(paragraphs) + "\n").encode()
            packages_path = binary / "Packages"
            packages_path.write_bytes(packages_encoded)
            (binary / "Packages.gz").write_bytes(deterministic_gzip(packages_encoded, epoch))
            by_hash = binary / "by-hash" / "SHA256"
            by_hash.mkdir(parents=True)
            for index in (packages_path, binary / "Packages.gz"):
                shutil.copyfile(index, by_hash / sha256_file(index))

        release = work / "dists" / args.suite / "Release"
        release.parent.mkdir(parents=True, exist_ok=True)
        indexes = sorted(path for path in (work / "dists" / args.suite / args.component).rglob("*")
                         if path.is_file() and "by-hash" not in path.parts)
        lines = [
            f"Origin: {args.origin}", f"Label: {args.label}", f"Suite: {args.suite}", f"Codename: {args.suite}",
            f"Date: {format_release_date(epoch)}", f"Valid-Until: {format_release_date(valid_until)}",
            f"Architectures: {' '.join(architectures)}", f"Components: {args.component}", "Acquire-By-Hash: yes", "SHA256:",
        ]
        for index in indexes:
            relative = index.relative_to(release.parent).as_posix()
            lines.append(f" {sha256_file(index)} {index.stat().st_size:16d} {relative}")
        release.write_text("\n".join(lines) + "\n", encoding="utf-8")

        gpg_base = ["gpg", "--batch", "--yes", "--homedir", str(gpg_home), "--local-user", fingerprint,
                    "--digest-algo", "SHA256", "--faked-system-time", f"{epoch}!"]
        run(gpg_base + ["--clearsign", "--output", str(release.parent / "InRelease"), str(release)])
        run(gpg_base + ["--detach-sign", "--output", str(release.parent / "Release.gpg"), str(release)])
        keyring = work / "cdnca-archive-keyring.gpg"
        keyring.write_bytes(run(["gpg", "--batch", "--homedir", str(gpg_home), "--export", fingerprint]))
        if not keyring.stat().st_size:
            fail("APT_KEY_INVALID", "exported trusted keyring is empty")

        for path in sorted(work.rglob("*")):
            os.utime(path, (epoch, epoch), follow_symlinks=False)
            os.chmod(path, 0o755 if path.is_dir() else 0o444)
        policy = {
            "component": args.component,
            "fingerprint": fingerprint,
            "key_version": key_version,
            "keyring_sha256": sha256_file(keyring),
            "not_after_epoch": valid_until,
            "not_before_epoch": epoch,
            "repository_generation": epoch,
            "schema": "cdnca.edge.apt-trust-policy/v1",
            "suite": args.suite,
        }
        policy_output.write_text(json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        os.chmod(policy_output, 0o444)
        output.parent.mkdir(parents=True, exist_ok=True)
        work.rename(output)
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise
    print(f"reason_code=APT_REPOSITORY_PUBLISHED path={output}")


def parse_release(encoded: bytes) -> tuple[dict[str, str], dict[str, tuple[int, str]]]:
    fields: dict[str, str] = {}
    hashes: dict[str, tuple[int, str]] = {}
    in_hashes = False
    for line in encoded.decode("utf-8").splitlines():
        if line == "SHA256:":
            in_hashes = True
            continue
        if in_hashes:
            match = re.fullmatch(r" ([0-9a-f]{64}) +([0-9]+) ([A-Za-z0-9._/-]+)", line)
            if not match or match.group(3) in hashes or ".." in Path(match.group(3)).parts:
                fail("APT_RELEASE_INVALID", "invalid Release SHA256 entry")
            hashes[match.group(3)] = (int(match.group(2)), match.group(1))
        else:
            key, separator, value = line.partition(": ")
            if separator != ": " or key in fields:
                fail("APT_RELEASE_INVALID", "invalid or duplicate Release field")
            fields[key] = value
    return fields, hashes


def command_verify(args: argparse.Namespace) -> None:
    repository = clean_absolute(args.repository, directory=True)
    policy_path = clean_absolute(args.policy)
    keyring = clean_absolute(args.trusted_keyring)
    now = uint(args.now_epoch, "current epoch", 100_000_000)
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail("APT_POLICY_INVALID", f"cannot parse trust policy: {error}")
    expected_keys = {"component", "fingerprint", "key_version", "keyring_sha256", "not_after_epoch",
                     "not_before_epoch", "repository_generation", "schema", "suite"}
    if set(policy) != expected_keys or policy["schema"] != "cdnca.edge.apt-trust-policy/v1":
        fail("APT_POLICY_INVALID", "trust policy shape or schema is invalid")
    if not FINGERPRINT.fullmatch(str(policy["fingerprint"])) or not isinstance(policy["key_version"], int) or policy["key_version"] < 1:
        fail("APT_POLICY_INVALID", "trusted key identity is invalid")
    if now < policy["not_before_epoch"] or now > policy["not_after_epoch"]:
        fail("APT_POLICY_EXPIRED", "repository trust policy is outside its validity window")
    if sha256_file(keyring) != policy["keyring_sha256"]:
        fail("APT_KEY_INVALID", "trusted keyring digest differs from policy")
    listing = run(["gpg", "--batch", "--show-keys", "--with-colons", str(keyring)]).decode()
    fingerprints = [line.split(":")[9].upper() for line in listing.splitlines() if line.startswith("fpr:")]
    if fingerprints != [policy["fingerprint"]]:
        fail("APT_KEY_INVALID", "trusted keyring fingerprint differs from policy")

    release_dir = repository / "dists" / policy["suite"]
    release = release_dir / "Release"
    inrelease = release_dir / "InRelease"
    detached = release_dir / "Release.gpg"
    for path in (release, inrelease, detached):
        if not path.is_file() or path.is_symlink():
            fail("APT_RELEASE_INVALID", f"missing signed repository metadata: {path.name}")
    decoded = Path(tempfile.mkstemp(prefix="cdnca-inrelease.")[1])
    try:
        run(["gpgv", "--keyring", str(keyring), "--output", str(decoded), str(inrelease)])
        run(["gpgv", "--keyring", str(keyring), str(detached), str(release)])
        if decoded.read_bytes() != release.read_bytes():
            fail("APT_SIGNATURE_INVALID", "InRelease payload differs from Release")
    finally:
        decoded.unlink(missing_ok=True)
    fields, hashes = parse_release(release.read_bytes())
    required = {
        "Suite": policy["suite"], "Codename": policy["suite"], "Components": policy["component"],
        "Acquire-By-Hash": "yes",
    }
    for key, expected in required.items():
        if fields.get(key) != expected:
            fail("APT_RELEASE_INVALID", f"Release field {key} differs from policy")
    for relative, (size, digest) in hashes.items():
        target = release_dir / relative
        if not target.is_file() or target.is_symlink() or target.stat().st_size != size or sha256_file(target) != digest:
            fail("APT_INDEX_INVALID", f"Release index differs from signed facts: {relative}")
        if target.name in ("Packages", "Packages.gz"):
            by_hash = target.parent / "by-hash" / "SHA256" / digest
            if not by_hash.is_file() or by_hash.read_bytes() != target.read_bytes():
                fail("APT_BY_HASH_INVALID", f"missing immutable by-hash index: {relative}")
    for architecture in fields.get("Architectures", "").split():
        packages = release_dir / policy["component"] / f"binary-{architecture}" / "Packages"
        if not packages.is_file():
            fail("APT_INDEX_INVALID", f"missing Packages index for {architecture}")
        for paragraph in packages.read_text(encoding="utf-8").strip().split("\n\n"):
            item = parse_control((paragraph + "\n").encode())
            target = repository / item.get("Filename", "")
            if (item.get("Architecture") != architecture or not target.is_file() or target.is_symlink() or
                    str(target.stat().st_size) != item.get("Size") or sha256_file(target) != item.get("SHA256")):
                fail("APT_PACKAGE_INVALID", f"package index fact mismatch for {item.get('Filename', 'unknown')}")
            inspect_deb(target)
    print(f"reason_code=APT_REPOSITORY_VERIFIED key_version={policy['key_version']} generation={policy['repository_generation']}")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build-package")
    for name in ("architecture", "version", "release-sequence", "source-date-epoch", "artifact", "sbom", "manifest",
                 "manifest-signature", "release-public-key", "rollback-key-version", "assets", "maintainer", "output-dir"):
        build.add_argument(f"--{name}", required=True)
    build.set_defaults(handler=command_build_package)
    inspect = commands.add_parser("inspect-package")
    inspect.add_argument("--package", required=True)
    inspect.add_argument("--expect-architecture", choices=sorted(ARCH_MACHINE), required=True)
    inspect.add_argument("--expect-version", required=True)
    inspect.add_argument("--require-lifecycle", required=True)
    inspect.add_argument("--require-path", action="append", default=[])
    inspect.set_defaults(handler=command_inspect_package)
    publish = commands.add_parser("publish")
    for name in ("packages-dir", "output-dir", "suite", "component", "origin", "label", "source-date-epoch",
                 "valid-until-epoch", "gpg-home", "fingerprint", "key-version", "policy-output"):
        publish.add_argument(f"--{name}", required=True)
    publish.set_defaults(handler=command_publish)
    verify = commands.add_parser("verify")
    for name in ("repository", "policy", "trusted-keyring", "now-epoch"):
        verify.add_argument(f"--{name}", required=True)
    verify.set_defaults(handler=command_verify)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        args.handler(args)
        return 0
    except PackagingError as error:
        print(f"reason_code={error.code} {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
