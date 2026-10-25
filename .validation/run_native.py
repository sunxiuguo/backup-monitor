"""Bounded, synthetic native regression. No real service, device, or account access."""
from __future__ import annotations

import base64
import concurrent.futures
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / ".validation"
BASE_COMMIT = "16736f652dca90b78f6d91ad60d707e54ad48dcd"
OLD_PYRIC_HASH = "d1b9b077af0b04f4e90b9aa2250b9409893460eec2bbac23d7ecd0bb1e5221af"
MAX_DOWNLOAD = 300_000_000
TRACKED = {}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def track(path):
    TRACKED[Path(path)] = digest(Path(path).read_bytes())


def verify_tracked():
    for path, expected in TRACKED.items():
        if not path.is_file() or digest(path.read_bytes()) != expected:
            raise ValueError(f"Immutable validation/source file changed: {path}")


def clean_environment():
    env = dict(os.environ)
    for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
        env.pop(key, None)
    env.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PIP_CONFIG_FILE="/dev/null", PIP_NO_CACHE_DIR="1", PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1")
    return env


def run(args, cwd, env=None, ok=0):
    result = subprocess.run([str(a) for a in args], cwd=cwd, env=clean_environment() if env is None else env, check=False)
    if result.returncode != ok:
        raise RuntimeError(f"Command failed ({result.returncode}, expected {ok}): {args}")


def fetch(item, destination):
    if not item["url"].startswith("https://files.pythonhosted.org/"):
        raise ValueError("Unapproved package host")
    with urllib.request.urlopen(item["url"], timeout=60) as response:
        data = response.read(item["size"] + 1)
    if len(data) != item["size"] or digest(data) != item["sha256"]:
        raise ValueError(f"Package bytes mismatch: {item['filename']}")
    destination.write_bytes(data)


def verify_pyric(source, wheel):
    with tarfile.open(source) as archive:
        expected = {
            member.name.split("/", 1)[1]: archive.extractfile(member).read()
            for member in archive.getmembers()
            if member.isfile() and "/pyric/" in member.name
        }
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        actual = {name: archive.read(name) for name in names if name.startswith("pyric/")}
        if actual != expected:
            raise ValueError("Built PyRIC code/data differ from audited sdist")
        if any(name.endswith(".pth") or "/scripts/" in name or name.endswith("entry_points.txt") for name in names):
            raise ValueError("Unexpected executable wheel addition")
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name).decode()
        if "Name: PyRIC\n" not in metadata or "Version: 0.1.6.3\n" not in metadata:
            raise ValueError("PyRIC identity mismatch")
        if "Requires-Dist:" in metadata or "Requires-Python:" in metadata:
            raise ValueError("Unexpected PyRIC dependency metadata")
        record_name = next(name for name in names if name.endswith(".dist-info/RECORD"))
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode())))
        if {row[0] for row in rows} != set(names):
            raise ValueError("RECORD does not cover wheel")
        for name, encoded, size in rows:
            if name == record_name:
                if encoded or size:
                    raise ValueError("Unexpected RECORD self hash")
                continue
            data = archive.read(name)
            actual_hash = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            if encoded != "sha256=" + actual_hash or int(size) != len(data):
                raise ValueError("Wheel RECORD hash/size mismatch")


def materialize_baseline(destination):
    for item in json.loads((INPUT / "baseline-tree.json").read_text()):
        path = item["path"]
        if "__pycache__" in path or path.endswith(".pyc") or ".." in Path(path).parts:
            raise ValueError("Unexpected baseline path")
        url = f"https://raw.githubusercontent.com/spezzuti/backup-monitor/{BASE_COMMIT}/{path}"
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(item["size"] + 1)
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if len(data) != item["size"] or blob != item["sha"]:
            raise ValueError(f"Baseline Gitblob mismatch: {path}")
        file = destination / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)


def add_source_guard(directory, expected):
    # Pytest loads this root plugin in the SAME process as all tests. No HA shims.
    code = '''import hashlib, importlib, importlib.metadata, pathlib, sys

def pytest_sessionstart(session):
    root = pathlib.Path(__file__).resolve().parent
    assert sys.version_info[:3] == (3, 14, 2)
    assert importlib.metadata.version("homeassistant") == "2026.10.2"
    import homeassistant
    assert root not in pathlib.Path(homeassistant.__file__).resolve().parents
    expected = EXPECTED
    for path, digest in expected.items():
        file = root / path
        assert hashlib.sha256(file.read_bytes()).hexdigest() == digest
        if path.startswith("custom_components/") and path.endswith(".py"):
            module = importlib.import_module(path[:-3].replace("/", "."))
            assert pathlib.Path(module.__file__).resolve() == file.resolve()
'''.replace("EXPECTED", repr(expected))
    (directory / "conftest.py").write_text(code)


def parse_report(path):
    root = ET.parse(path).getroot()
    return list(root.iter("testcase"))


def check_green(cases, count):
    if len(cases) != count or any(list(c.iter("failure")) or list(c.iter("error")) or list(c.iter("skipped")) for c in cases):
        raise ValueError("Expected exact non-skipped green test count")


def check_red(cases):
    if len(cases) != 1:
        raise ValueError("Expected exactly one red test")
    case = cases[0]
    if case.get("name") != "test_result_workflow[old_fatal_then_success]" or case.get("classname") != "tests.test_duplicati_result_workflow":
        raise ValueError("Unexpected red node")
    failures = list(case.iter("failure"))
    if len(failures) != 1 or list(case.iter("error")) or list(case.iter("skipped")):
        raise ValueError("Expected exact assertion failure, not setup error or skip")
    details = failures[0].get("message", "") + (failures[0].text or "")
    if "assert 'error' == 'success'" not in details or 'job["last_result"] == expected' not in details:
        raise ValueError("Baseline failure is not the preselected sticky-error assertion")


def execute():
    if sys.version_info[:3] != (3, 14, 2):
        raise RuntimeError("Require exact official Python 3.14.2")
    if shutil.disk_usage(tempfile.gettempdir()).free < 2_000_000_000:
        raise RuntimeError("Require at least 2GB free in independent runner")
    validation = json.loads((INPUT / "validation-hashes.json").read_text())
    for relative, expected in validation.items():
        path = ROOT / relative
        if digest(path.read_bytes()) != expected:
            raise ValueError(f"Validation implementation/input changed: {relative}")
        track(path)
    track(INPUT / "validation-hashes.json")
    print(f"Validation commit: {os.environ.get('GITHUB_SHA', 'local-unpublished')}", flush=True)
    candidate_hashes = json.loads((INPUT / "candidate-hashes.json").read_text())
    for relative, sha in candidate_hashes.items():
        if digest((ROOT / relative).read_bytes()) != sha:
            raise ValueError(f"Reviewed candidate changed: {relative}")
        track(ROOT / relative)
    wheels = json.loads((INPUT / "wheels.json").read_text())
    build_inputs = json.loads((INPUT / "build-inputs.json").read_text())
    lock = (INPUT / "requirements.lock").read_text()
    if len(wheels) != 107 or sum(w["size"] for w in wheels) + sum(w["size"] for w in build_inputs.values()) > MAX_DOWNLOAD:
        raise ValueError("Package count/download budget changed")
    requirements = {}
    for block in re.split(r"(?=^[\w.-]+==)", lock, flags=re.M):
        match = re.match(r"([\w.-]+)==([^\s\\]+)", block)
        if match:
            requirements[match[1]] = (match[2], set(re.findall(r"--hash=sha256:([a-f0-9]{64})", block)))
    if {w["name"] for w in wheels} != set(requirements):
        raise ValueError("Manifest/lock package mismatch")
    for wheel in wheels:
        if (wheel["version"] != requirements[wheel["name"]][0] or wheel["sha256"] not in requirements[wheel["name"]][1]):
            raise ValueError("Manifest/lock version/hash mismatch")
    temporary = Path(tempfile.mkdtemp(prefix="duplicati-native-"))
    print(f"Independent synthetic workspace: {temporary}", flush=True)
    wheelhouse = temporary / "wheels"
    buildhouse = temporary / "build-inputs"
    wheelhouse.mkdir()
    buildhouse.mkdir()
    downloads = [(w, wheelhouse / w["filename"]) for w in wheels if w["name"].lower() != "pyric"]
    downloads += [(w, buildhouse / w["filename"]) for w in build_inputs.values()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda args: fetch(*args), downloads))
    build_env = temporary / "build-env"
    run([sys.executable, "-m", "venv", build_env], temporary)
    build_python = build_env / "bin/python"
    build_lock = temporary / "build.lock"
    build_lock.write_text("".join(f"{buildhouse / build_inputs[name]['filename']} --hash=sha256:{build_inputs[name]['sha256']}\n" for name in ("setuptools", "wheel")))
    run([build_python, "-m", "pip", "install", "--no-index", "--no-deps", "--require-hashes", "-r", build_lock], temporary)
    source = buildhouse / build_inputs["pyric"]["filename"]
    extracted = temporary / "source"
    extracted.mkdir()
    with tarfile.open(source) as archive:
        archive.extractall(extracted, filter="data")
    env = clean_environment()
    env["SOURCE_DATE_EPOCH"] = "1780000000"
    run([build_python, "setup.py", "bdist_wheel", "--dist-dir", wheelhouse], extracted / "PyRIC-0.1.6.3", env)
    built = wheelhouse / "pyric-0.1.6.3-py2.py3-none-any.whl"
    verify_pyric(source, built)
    new_hash = digest(built.read_bytes())
    if lock.count(OLD_PYRIC_HASH) != 1:
        raise ValueError("Unexpected PyRIC original lock hash")
    runtime_lock = temporary / "runtime.lock"
    runtime = lock.replace(OLD_PYRIC_HASH, new_hash)
    if runtime.replace(new_hash, OLD_PYRIC_HASH) != lock:
        raise ValueError("Changed unrelated lock bytes")
    runtime_lock.write_text(runtime)
    print(json.dumps({"original_lock_sha256": digest(lock.encode()), "runtime_lock_sha256": digest(runtime.encode()), "pyric_wheel_sha256": new_hash}), flush=True)
    runtime_env = temporary / "runtime-env"
    run([sys.executable, "-m", "venv", runtime_env], temporary)
    python = runtime_env / "bin/python"
    run([python, "-m", "pip", "install", "--no-index", "--find-links", wheelhouse, "--only-binary=:all:", "--require-hashes", "-r", runtime_lock], temporary)
    baseline = temporary / "baseline"
    baseline.mkdir()
    materialize_baseline(baseline)
    candidate = temporary / "candidate"
    shutil.copytree(baseline, candidate)
    for relative in candidate_hashes:
        out = candidate / relative
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, out)
    for directory in (baseline, candidate):
        if list(directory.rglob("*.pyc")) or list(directory.rglob("__pycache__")):
            raise ValueError("Unexpected precompiled code")
    production = [p for p in candidate_hashes if p.startswith("custom_components/")]
    add_source_guard(baseline, {p: digest((baseline / p).read_bytes()) for p in production})
    add_source_guard(candidate, {p: digest((candidate / p).read_bytes()) for p in production})
    # Both directories contain the same new tests before their frozen snapshot.
    for relative in candidate_hashes:
        if relative.startswith("tests/"):
            out = baseline / relative
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, out)
    for directory in (baseline, candidate):
        for path in directory.rglob("*"):
            if path.is_file():
                track(path)
    verify_tracked()
    pytest = [python, "-m", "pytest", "-p", "pytest_asyncio.plugin", "-o", "asyncio_mode=auto", "-q"]
    test_env = dict(env, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    baseline_report = temporary / "baseline-original.xml"
    run(pytest + ["tests/test_backrest_provider.py", "tests/test_duplicati_provider.py", f"--junitxml={baseline_report}"], baseline, test_env)
    original_count = 5
    check_green(parse_report(baseline_report), original_count)
    red_report = temporary / "baseline-red.xml"
    node = "tests/test_duplicati_result_workflow.py::test_result_workflow[old_fatal_then_success]"
    run(pytest + [node, f"--junitxml={red_report}"], baseline, test_env, ok=1)
    check_red(parse_report(red_report))
    candidate_report = temporary / "candidate.xml"
    run(pytest + [f"--junitxml={candidate_report}"], candidate, test_env)
    check_green(parse_report(candidate_report), original_count + 33)
    run([runtime_env / "bin/ruff", "check", *production, "tests/test_duplicati_result_workflow.py"], candidate, test_env)
    for report in (baseline_report, red_report, candidate_report):
        print(report.name + "\n" + report.read_text(), flush=True)
    print("Native original/red/candidate checks passed; live API/HA startup NOT tested.", flush=True)


def main():
    try:
        execute()
    finally:
        # Even failed builds/imports/tests must not silently mutate frozen inputs.
        verify_tracked()


if __name__ == "__main__":
    main()
