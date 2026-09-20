#!/usr/bin/env python3
"""Release guards and native smoke checks; packaging belongs to GoReleaser."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def version(tag):
    number = r"(?:0|[1-9][0-9]*)"
    identifier = r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    pattern = rf"v{number}\.{number}\.{number}(?:-{identifier}(?:\.{identifier})*)?"
    require(re.fullmatch(pattern, tag), "expected vMAJOR.MINOR.PATCH[-prerelease]")
    return tag[1:]


def output(*args, **kwargs):
    return subprocess.check_output(args, text=True, timeout=60, **kwargs).strip()


def refuse_existing(tag, pages):
    # Include drafts and all pages. API/authentication failures must fail closed.
    require(not any(r["tag_name"] == tag for page in pages for r in page),
            "release already exists; never overwrite it (see docs/RELEASING.md)")


def preflight(tag, repository):
    version(tag)
    commit = output("git", "rev-parse", "HEAD")
    require(output("git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}") == commit,
            "tag does not point to checked-out commit")
    require(not output("git", "status", "--porcelain"), "release requires a clean checkout")
    pages = json.loads(output("gh", "api", "--paginate", "--slurp",
                              f"repos/{repository}/releases?per_page=100"))
    refuse_existing(tag, pages)
    print(f"Release preflight passed: {tag} at {commit}")


def verify_assets(tag, directory):
    ver = version(tag)
    names = {f"scheck_{ver}_{system}_{arch}.tar.gz"
             for system in ("linux", "darwin") for arch in ("amd64", "arm64")}
    require({p.name for p in directory.iterdir()} == names | {"checksums.txt"},
            "expected exactly four archives and checksums.txt")
    hashes = {}
    for line in (directory / "checksums.txt").read_text().splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (\S+)", line)
        require(match is not None, "invalid checksum line")
        digest, name = match.groups()
        require(name not in hashes, "duplicate checksum entry")
        hashes[name] = digest
    require(set(hashes) == names, "checksum inventory differs from expected archives")
    for name, digest in hashes.items():
        archive = directory / name
        require(hashlib.sha256(archive.read_bytes()).hexdigest() == digest,
                f"checksum mismatch: {name}")
        with tarfile.open(archive, "r:gz") as tar:
            members = tar.getmembers()
            require(len(members) == 2 and {m.name for m in members} == {"scheck", "LICENSE"},
                    f"unexpected archive contents: {name}")
            require(all(m.isfile() for m in members), "archive must contain regular files only")
            require(tar.getmember("scheck").mode & 0o111, "binary must be executable")
            require(tar.extractfile("LICENSE").read() == Path("LICENSE").read_bytes(),
                    "archive license differs from repository license")
    return ver


def smoke_binary(binary, tag, cwd):
    # Discovery never assesses a host. Isolate it from user/project configuration.
    env = dict(os.environ, HOME=str(cwd), XDG_CONFIG_HOME=str(cwd))
    require(output(str(binary), "--version", cwd=cwd, env=env) == f"scheck version {tag}",
            "binary version does not match tag")
    for kind, args in (("catalog", ["catalog"]),
                       ("explain", ["explain", "sshd.config"])):
        doc = json.loads(output(str(binary), *args, "--format", "json", cwd=cwd, env=env))
        require(doc["kind"] == kind and doc["scheck_version"] == tag,
                "discovery metadata does not match release")
        require(doc["checks"] and any(c["id"] == "sshd.config" for c in doc["checks"]),
                "discovery lacks expected catalog entry")
        if kind == "explain":
            require(all(c["id"] == "sshd.config" for c in doc["checks"]),
                    "explain returned unrelated checks")


def smoke(tag, directory):
    ver = verify_assets(tag, directory)
    system = {"Linux": "linux", "Darwin": "darwin"}[platform.system()]
    arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[platform.machine()]
    name = f"scheck_{ver}_{system}_{arch}.tar.gz"
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        binary = cwd / "scheck"
        with tarfile.open(directory / name, "r:gz") as tar:
            binary.write_bytes(tar.extractfile("scheck").read())
        binary.chmod(0o755)
        smoke_binary(binary, tag, cwd)
    print(f"PASS: all archive checksums/contents; native {system}/{arch} version/catalog/explain")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["preflight", "smoke"])
    parser.add_argument("tag")
    parser.add_argument("target", help="owner/repo for preflight; downloaded directory for smoke")
    args = parser.parse_args()
    if args.command == "preflight":
        preflight(args.tag, args.target)
    else:
        smoke(args.tag, Path(args.target))
