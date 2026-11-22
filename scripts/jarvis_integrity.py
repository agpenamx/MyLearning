#!/usr/bin/env python3
"""Read-only audit of JARVIS public-reference files. No network or writes.
Git blob SHA-1 is an existing Git identifier, NOT a post-quantum guarantee.
SHA3-512 is a content fingerprint, NOT a digital signature.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

SECRET_PATTERNS = [
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(rb"(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}"),
]

def verify(root, manifest):
    root = pathlib.Path(root).resolve()
    doc = json.loads(pathlib.Path(manifest).read_text(encoding="utf-8"))
    entries = doc["files"]
    problems, output = [], []
    if not entries:
        problems.append("manifest is empty")
    for relative, expected in sorted(entries.items()):
        path = root / relative
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            problems.append(f"missing, symlink or unsafe path: {relative}")
            continue
        data = path.read_bytes()
        if len(data) > 1_000_000:
            problems.append(f"oversize source: {relative}")
        blob_sha = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\x00" + data).hexdigest()
        if blob_sha != expected:
            problems.append(f"changed since approved baseline: {relative}")
        for pattern in SECRET_PATTERNS:
            if pattern.search(data):
                problems.append(f"possible credential in: {relative}")
        output.append({"path": relative, "git_blob_sha1": blob_sha,
                       "sha3_512": hashlib.sha3_512(data).hexdigest(),
                       "bytes": len(data), "baseline_match": blob_sha == expected})
    return {"result": "PASS" if not problems else "FAIL",
            "checked": len(output), "issues": problems, "fingerprints": output,
            "boundary": "legacy Git blob IDs + SHA3-512; NO post-quantum signing"}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--manifest", default="security/jarvis_baseline.json")
    args = parser.parse_args()
    result = verify(args.root, args.manifest)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["result"] == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
