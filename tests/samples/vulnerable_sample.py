"""
Intentionally vulnerable sample file used for SAST testing.
DO NOT USE IN PRODUCTION.
"""

import hashlib
import os
import pickle
import random
import socket
import ssl
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

import requests
import yaml


def trigger_eval(user_input: str):
    # SEC001: eval
    return eval(user_input)


def trigger_exec(code_str: str):
    # SEC001: exec
    exec(code_str)


def trigger_os_system(cmd: str):
    # SEC001: os.system
    os.system(cmd)


def trigger_subprocess(target_ip: str):
    # SEC002: subprocess shell=True
    subprocess.Popen(f"ping {target_ip}", shell=True)


def trigger_weak_crypto(password: str):
    # SEC003: MD5 without usedforsecurity=False
    return hashlib.md5(password.encode()).hexdigest()


def trigger_pickle_load(raw_data: bytes):
    # SEC004: pickle loads
    return pickle.loads(raw_data)


def trigger_yaml_load(payload: str):
    # SEC004: yaml.load without SafeLoader
    return yaml.load(payload)


def trigger_insecure_temp():
    # SEC005: tempfile.mktemp
    return tempfile.mktemp(suffix=".tmp")


def trigger_hardcoded_secrets():
    # SEC006: Hardcoded secret token
    api_key = "AKIA1234567890ABCDEF"  # Real AWS ID format
    return api_key


def trigger_sql_injection(cursor, user_id: str):
    # SEC007: SQL Injection with f-string
    cursor.execute(f"SELECT * FROM accounts WHERE id = {user_id}")


def trigger_xxe(xml_data: str):
    # SEC008: Vulnerable standard XML parser
    return ET.fromstring(xml_data)


def trigger_bind_all_interfaces():
    # SEC009: Binding to 0.0.0.0
    s = socket.socket()
    s.bind(("0.0.0.0", 8080))


def trigger_insecure_ssl(url: str):
    # SEC010: verify=False
    return requests.get(url, verify=False)


def trigger_weak_random():
    # SEC011: Weak random token generation
    token = str(random.randint(100000, 999999))
    return token


def trigger_assert_usage(user):
    # SEC012: Insecure assert for access control
    assert user.is_admin, "Unauthorized"


def trigger_zip_slip(tar_path: str):
    # SEC013: extractall without filter
    with tarfile.open(tar_path) as tar:
        tar.extractall("/tmp/extracted")


def trigger_debug_mode():
    # SEC014: DEBUG = True hardcoded
    DEBUG = True
    return DEBUG


def trigger_path_traversal(user_filename: str):
    # SEC015: Path traversal via dynamic open()
    with open(f"/var/data/{user_filename}", "r") as f:
        return f.read()
