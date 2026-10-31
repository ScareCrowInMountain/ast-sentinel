"""
Secure counterpart file demonstrating compliant patterns.
Should yield 0 security findings.
"""

import ast
import hashlib
import os
import secrets
import socket
import ssl
import subprocess
import tarfile
import tempfile
from pathlib import Path

import requests
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


def safe_credentials():
    # Safe alternative: Reading from environment variables
    return os.environ.get("API_KEY", "")


def safe_sql_query(cursor, user_id: int):
    # Safe alternative: Parameterized query tuple
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))


def safe_network_binding():
    # Safe alternative: Binding exclusively to localhost
    s = socket.socket()
    s.bind(("127.0.0.1", 8080))


def safe_ssl_request(url: str):
    # Safe alternative: Standard verified TLS request
    return requests.get(url, verify=True)


def safe_token_generation():
    # Safe alternative: Cryptographically secure randomness
    return secrets.token_hex(32)


def safe_archive_extraction(tar_path: str):
    # Safe alternative: Python 3.12+ safe filter
    with tarfile.open(tar_path) as tar:
        tar.extractall("/tmp/safe", filter="data")


def safe_file_reading(user_filename: str):
    # Safe alternative: Validated and normalized path
    base = Path("/var/data").resolve()
    target = (base / user_filename).resolve()
    if base in target.parents:
        return target.read_text(encoding="utf-8")
    raise ValueError("Path traversal attempt detected")


def suppressed_finding_demonstration():
    # Inline suppression with # nosec prevents false positives
    eval("1 + 1")  # nosec: SEC001
