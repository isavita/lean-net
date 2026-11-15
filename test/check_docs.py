#!/usr/bin/env python3
"""Compile the documented Lean code and exercise every complete server snippet.

Run from the repository root after installing test/requirements-http2.txt.
Git dependency clauses are checked in fresh consumers. Server snippets use the
working tree, temporary certificates/files, free ports, and independent HTTP
clients; no system trust or persistent application files are changed.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from http2_test_support import H2Client


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tls/test"))
from tls_test_support import openssl_binary

STATIC_BODY = b"<!doctype html><title>Documentation example</title>\n"
UPSTREAM_BODY = b"documentation upstream\n"


@dataclass(frozen=True)
class Block:
    path: Path
    line: int
    language: str
    code: str

    @property
    def label(self):
        return f"{self.path.relative_to(ROOT)}:{self.line}"


def documentation_files():
    """Collect repository Markdown plus public source files used by doc-gen4."""
    markdown = []
    for directory, children, files in os.walk(ROOT):
        children[:] = sorted(name for name in children if name not in {
            ".git", ".lake", "__pycache__", ".venv"})
        markdown.extend(Path(directory) / name for name in sorted(files) if name.endswith(".md"))
    lean = [ROOT / "LeanNet.lean", ROOT / "tls/LeanNetTLS.lean", ROOT / "docs/LeanNetDocs.lean"]
    lean += sorted((ROOT / "LeanNet").rglob("*.lean"))
    lean += sorted((ROOT / "tls/LeanNetTLS").rglob("*.lean"))
    lean += sorted((ROOT / "examples").glob("*.lean"))
    return sorted(set(markdown + lean))


def blocks_in(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    opened = None
    for number, line in enumerate(lines, 1):
        match = re.match(r"^\s*(`{3,}|~{3,})([^`~]*)$", line)
        if not match:
            if opened is not None:
                opened[3].append(line)
            continue
        fence, language = match.groups()
        if opened is None:
            opened = [fence[0], len(fence), (language.strip().lower(), number + 1), []]
        elif fence[0] == opened[0] and len(fence) >= opened[1] and not language.strip():
            (language, start), content = opened[2], opened[3]
            yield Block(path, start, language, "\n".join(content) + "\n")
            opened = None
        else:
            opened[3].append(line)
    if opened is not None:
        raise AssertionError(f"{path.relative_to(ROOT)}:{opened[2][1]}: unclosed documentation fence")


def command(args, *, cwd=ROOT, timeout=240):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(f"command failed: {args}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def lean_string(text):
    # JSON and Lean use the same escapes for these policy samples.
    return json.dumps(text, ensure_ascii=False)


def policy_block(block):
    first = next((line.strip() for line in block.code.splitlines()
                  if line.strip() and not line.lstrip().startswith("#")), "")
    return block.language in {"", "text", "gate"} and first.startswith((
        "limits ", "ratelimit ", "backend ", "host ", "on unknown-host "))


def native_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def rewrite_port(source, port, label):
    source, replacements = re.subn(r'("127\.0\.0\.1"\s+)(8080|8443)\b',
                                   lambda match: match[1] + str(port), source)
    if replacements != 1:
        raise AssertionError(f"{label}: complete server example must have one explicit loopback listener")
    return source


def classify_program(block, previous):
    source = block.code
    if source.lstrip().startswith("require "):
        return "require", source
    if source.lstrip().startswith("LeanNetTLS.ReactorServer.serveFactory"):
        if not previous:
            raise AssertionError(f"{block.label}: TLS expression has no preceding app/config example")
        # The prose explicitly asks readers to reuse the preceding app/config.
        prefix, count = re.subn(r"\ndef main\s*:\s*IO Unit\s*:=.*\Z", "\n", previous, flags=re.S)
        if count != 1:
            raise AssertionError(f"{block.label}: cannot identify the preceding main to replace")
        source = "import LeanNetTLS\n" + prefix + "\ndef main : IO Unit :=\n" + "".join(
            "  " + line + "\n" for line in source.splitlines())
    if not re.search(r"\bdef main\b", source):
        return "fragment", source
    if "Gate.withLive" in source:
        return "gateway", source
    if "Static.serveRoot" in source:
        return "static", source
    if "LeanNetTLS" in source:
        return "tls", source
    return "plain", source


def check_require(block, directory):
    directory.mkdir()
    (directory / "lean-toolchain").write_text((ROOT / "lean-toolchain").read_text())
    (directory / "lakefile.lean").write_text(
        "import Lake\nopen Lake DSL\npackage doc_dependency_consumer\n" + block.code)
    command(["lake", "update"], cwd=directory)
    module = "LeanNetTLS" if "lean-net-tls" in block.code else "LeanNet"
    command(["lake", "build", module], cwd=directory)
    print(f"PASS dependency {block.label}", flush=True)


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(UPSTREAM_BODY)))
        self.end_headers()
        self.wfile.write(UPSTREAM_BODY)

    def log_message(self, *_):
        pass


@contextmanager
def upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "documentation upstream did not stop"


def certificate(directory):
    command([openssl_binary(), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", "key.pem", "-out", "chain.pem", "-days", "1",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], cwd=directory)


def tls_context(directory, protocols):
    import ssl
    context = ssl.create_default_context(cafile=str(directory / "chain.pem"))
    context.set_alpn_protocols(protocols)
    return context


def exercise(binary, kind, port, directory, policy):
    (directory / "public").mkdir(exist_ok=True)
    (directory / "public/index.html").write_bytes(STATIC_BODY)
    if kind == "tls":
        certificate(directory)
    with upstream() as upstream_port:
        if kind == "gateway":
            assert policy is not None, "gateway example has no documented policy"
            (directory / "gate.policy").write_text(policy.replace(
                "127.0.0.1:9000", f"127.0.0.1:{upstream_port}"))
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        with tempfile.TemporaryFile(mode="w+") as log:
            process = subprocess.Popen([str(binary)], cwd=directory, stdout=log, stderr=log,
                                       creationflags=flags)
            try:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        log.seek(0)
                        raise AssertionError(f"{kind} server exited at startup:\n{log.read()}")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise AssertionError(f"{kind} server startup timed out")
                        time.sleep(.025)
                authority = "api.example.com" if kind == "gateway" else "localhost"
                target = "/items/docs" if kind == "gateway" else "/"
                expected = UPSTREAM_BODY if kind == "gateway" else STATIC_BODY if kind == "static" else b"ok\n"
                if kind == "tls":
                    client = http.client.HTTPSConnection("localhost", port, timeout=5,
                        context=tls_context(directory, ["http/1.1"]))
                else:
                    client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                try:
                    client.request("GET", target, headers={"Host": authority})
                    response = client.getresponse()
                    assert response.status == 200, (kind, response.status)
                    assert response.read() == expected, kind
                finally:
                    client.close()
                if kind == "gateway":
                    client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    try:
                        client.request("GET", "/", headers={"Host": "unlisted.example"})
                        response = client.getresponse()
                        assert response.status == 421, response.status
                        response.read()
                    finally:
                        client.close()
                if kind == "tls":
                    context = tls_context(directory, ["h2", "http/1.1"])
                    raw = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
                                              server_hostname="localhost")
                    assert raw.selected_alpn_protocol() == "h2"
                    h2 = H2Client(sock=raw, authority=authority.encode(), scheme=b"https")
                else:
                    h2 = H2Client(port, authority=authority.encode())
                try:
                    h2.request(1, target.encode())
                    assert h2.response(1) == expected, kind
                    assert not h2.goaways and not h2.resets, kind
                finally:
                    h2.close()
            finally:
                if process.poll() is None:
                    process.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGINT)
                try:
                    result = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise AssertionError(f"{kind} server did not stop within its drain budget")
                log.seek(0)
                assert result == 0, f"{kind} server exit {result}:\n{log.read()}"


def main():
    os.environ.setdefault("LEAN_NUM_THREADS", "2")
    blocks = [block for path in documentation_files() for block in blocks_in(path)]
    lean = [block for block in blocks if block.language in {"lean", "lean4"}]
    policies = [block for block in blocks if policy_block(block)]
    if not lean or not policies:
        raise AssertionError("documentation inventory unexpectedly has no Lean or policy examples")
    shell = [block for block in blocks if block.language in {"sh", "bash", "shell"}]
    other = [block for block in blocks if block not in lean + policies + shell]
    for block in other:
        if block.language == "mermaid":
            continue
        if block.language in {"json", "jsonc"}:
            json.loads(block.code)
            continue
        raise AssertionError(f"{block.label}: unclassified documentation fence {block.language!r}")
    for block in shell:
        result = subprocess.run(["bash", "-n"], input=block.code, text=True, capture_output=True)
        assert result.returncode == 0, f"{block.label}: {result.stderr}"
    with tempfile.TemporaryDirectory(prefix="lean-net-doc-examples-") as temporary:
        directory = Path(temporary)
        programs, fragments, previous = [], [], {}
        for index, block in enumerate(lean, 1):
            kind, source = classify_program(block, previous.get(block.path))
            if kind == "require":
                check_require(block, directory / f"dependency-{index}")
                continue
            previous[block.path] = source
            if kind == "fragment":
                fragments.append((block, source))
            else:
                port = native_port()
                programs.append((block, kind, rewrite_port(source, port, block.label), port))
        workspace = directory / "programs"
        workspace.mkdir()
        (workspace / "lean-toolchain").write_text((ROOT / "lean-toolchain").read_text())
        targets = [f"doc-{index}" for index in range(len(programs))]
        config = ('import Lake\nopen Lake DSL\npackage doc_examples\n'
                  f'require «lean-net-tls» from "{(ROOT / "tls").as_posix()}"\n')
        for index, (_, _, source, _) in enumerate(programs):
            config += f'@[default_target] lean_exe «doc-{index}» where\n  root := `Doc{index}\n'
            (workspace / f"Doc{index}.lean").write_text(source)
        (workspace / "lakefile.lean").write_text(config)
        command(["lake", "update"], cwd=workspace)
        command(["lake", "build", *targets, "LeanNet.Gate.Literal"], cwd=workspace)
        for index, (block, source) in enumerate(fragments):
            path = workspace / f"Fragment{index}.lean"
            path.write_text(source)
            command(["lake", "env", "lean", str(path)], cwd=workspace)
            print(f"PASS Lean declarations {block.label}", flush=True)
        for index, block in enumerate(policies):
            path = workspace / f"Policy{index}.lean"
            path.write_text('import LeanNet.Gate.Literal\n'
                            f'def policy : LeanNet.Gate.Spec := gate% {lean_string(block.code)}\n')
            command(["lake", "env", "lean", str(path)], cwd=workspace)
            print(f"PASS policy {block.label}", flush=True)
        policy = next((block.code for block in policies if block.path == ROOT / "docs/gateway.md"), None)
        suffix = ".exe" if sys.platform == "win32" else ""
        for index, (block, kind, _, port) in enumerate(programs):
            exercise(workspace / f".lake/build/bin/doc-{index}{suffix}", kind, port, workspace, policy)
            print(f"PASS HTTP/1 + HTTP/2 startup, response and shutdown {block.label}", flush=True)
    print(f"Checked {len(lean)} Lean blocks, {len(policies)} policies and {len(shell)} shell blocks; "
          f"ran {len(programs)} complete server programs. Shell blocks receive syntax checks only.")


if __name__ == "__main__":
    main()
