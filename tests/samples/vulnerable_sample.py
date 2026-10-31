"""
Intentionally vulnerable sample file used for SAST testing.
DO NOT USE IN PRODUCTION.
"""

import hashlib
import os
import pickle
import subprocess
import tempfile
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
