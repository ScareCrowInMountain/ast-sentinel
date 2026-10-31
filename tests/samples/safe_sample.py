"""
Secure counterpart file demonstrating compliant patterns.
Should yield 0 security findings.
"""

import ast
import hashlib
import subprocess
import tempfile

import yaml


def safe_eval(literal_data: str):
    # Safe alternative: literal_eval
    return ast.literal_eval(literal_data)


def safe_subprocess(cmd: list):
    # Safe alternative: explicit argument list and shell=False (default)
    return subprocess.run(["ls", "-la"], check=True)


def safe_crypto(data: bytes):
    # Safe alternative: modern SHA256
    return hashlib.sha256(data).hexdigest()


def safe_checksum_with_md5(data: bytes):
    # Safe alternative: MD5 explicitly marked as non-security
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def safe_yaml_parsing(payload: str):
    # Safe alternative: yaml.safe_load
    return yaml.safe_load(payload)


def safe_tempfile():
    # Safe alternative: NamedTemporaryFile
    with tempfile.NamedTemporaryFile() as tmp:
        return tmp.name
