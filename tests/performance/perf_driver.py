#!/usr/bin/env python3
"""OpenMail scale benchmark: the real `openmail-mcp` binary, driven as an MCP client over stdio,
against a real GreenMail IMAP server provisioned with N users. Python >= 3.8, stdlib only.

Per account count N it measures: startup-to-initialize, idle RSS (untouched and after every
account was used), cold connection establishment, serial search latency p50/p95, concurrent
mixed load (search + get_message) throughput, peak RSS (VmHWM), CPU, the peak number of
simultaneous IMAP sessions (exact count at a TLS proxy in front of GreenMail, cross-checked by
sampling /proc/net/tcp), and recovery time after `docker kill` + restart of GreenMail.

GreenMail speaks plain IMAP only and the binary refuses plain IMAP by design, so a small asyncio
TLS proxy with a private CA (handed to the binary via SSL_CERT_FILE) fronts it. The proxy adds
latency of its own; every number here is "binary + proxy + GreenMail in Docker on this host".

Nothing is estimated: a phase that fails records the failure instead of a number.
"""
import argparse
import asyncio
import json
import os
import random
import re
import shutil
import signal
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PROVISION = ROOT / "tests" / "infra" / "provision_users.py"
COMPOSE_PERF = ROOT / "tests" / "infra" / "docker-compose.perf.yml"
CONTAINER = "openmail-perf-greenmail"
GM_IMAP_PORT = 23143
GM_API_PORT = 28080
KEYWORD = "quarterly-invoice"
KEYWORD_EVERY = 10  # must match provision_users.py
CLK_TCK = os.sysconf("SC_CLK_TCK")
IDLE_SETTLE_S = 3.0
SAMPLE_INTERVAL_S = 0.02
CONCURRENCY = 32  # in-flight requests during the mixed-load phase; > 8 so the global cap binds
# Mixed-load request budget: enough for stable p95 (hundreds of samples) yet bounded wall time.
LOAD_REQUESTS = 100
SERIAL_SEARCHES = 60
# The server rate-limits tool calls with compile-time constants (crates/openmail-mcp/src/access.rs:
# global 120 burst + 20/s, per account 60 burst + 10/s). Waiting this long lets both buckets refill
# completely (120 / 20 per s = 6 s) so a measured phase starts with a full burst budget.
BUCKET_REFILL_S = 7.0
# Probe request count: far above the 120-token global burst so the sustained refill rate shows.
PROBE_REQUESTS = 400
# Recovery-phase workers are paced so that failed calls during the outage do not drain the rate
# limiter and make "recovery" look slower than the IMAP path actually is.
RECOVERY_PACE_S = 0.4
REPLY_TIMEOUT_S = 90.0


def user_name(i):
    return "perf%03d" % i


def password(i):
    return "pw-%s-perf" % user_name(i)


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p / 100.0 * len(s) + 0.5)) - 1))
    return s[k]


def ms(x):
    return None if x is None else round(x * 1000.0, 2)


# ---------------------------------------------------------------- /proc helpers
def read_status(pid):
    out = {}
    try:
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith(("VmRSS:", "VmHWM:", "Threads:")):
                    k, v = line.split(":", 1)
                    out[k] = int(v.split()[0])
    except OSError:
        pass
    return out


def cpu_ticks(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            rest = f.read().rsplit(")", 1)[1].split()
        return int(rest[11]) + int(rest[12])  # utime + stime
    except (OSError, IndexError, ValueError):
        return 0


def established_on_port(port):
    """ESTABLISHED sockets whose LOCAL port is `port` (same data `ss -tn` prints)."""
    n = 0
    hexport = ":%04X" % port
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    cols = line.split()
                    if cols[3] == "01" and cols[1].endswith(hexport):
                        n += 1
        except OSError:
            pass
    return n


# ---------------------------------------------------------------- PKI + TLS proxy
def make_pki(d):
    d.mkdir(parents=True, exist_ok=True)
    ca_key, ca_pem, key, csr, pem, ext = (d / n for n in ("ca.key", "ca.pem", "k.key", "k.csr", "k.pem", "ext.cnf"))
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca_pem),
        "-days", "2", "-subj", "/CN=openmail-perf-ca")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN=localhost")
    ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n")
    run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_pem), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(pem), "-days", "2", "-extfile", str(ext))
    return ca_pem, pem, key


class TlsProxy:
    """TLS terminator in front of GreenMail that counts simultaneous client sessions exactly."""

    def __init__(self, cert, key, upstream_port):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(cert), str(key))
        self.upstream_port = upstream_port
        self.open = 0
        self.peak = 0
        self.accepted = 0
        self.port = 0
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=self.ctx, backlog=512)
        self.port = self.server.sockets[0].getsockname()[1]

    def reset_peak(self):
        self.peak = self.open
        self.accepted = 0

    async def _handle(self, cr, cw):
        self.open += 1
        self.accepted += 1
        self.peak = max(self.peak, self.open)
        uw = None
        try:
            ur, uw = await asyncio.open_connection("127.0.0.1", self.upstream_port)

            async def pipe(r, w):
                try:
                    while True:
                        b = await r.read(65536)
                        if not b:
                            break
                        w.write(b)
                        await w.drain()
                except (ConnectionError, ssl.SSLError, OSError):
                    pass
                finally:
                    try:
                        w.close()
                    except OSError:
                        pass

            await asyncio.gather(pipe(cr, uw), pipe(ur, cw))
        except OSError:
            pass
        finally:
            self.open -= 1
            for w in (cw, uw):
                try:
                    if w is not None:
                        w.close()
                except OSError:
                    pass


# ---------------------------------------------------------------- MCP client
class Mcp:
    def __init__(self, proc):
        self.proc = proc
        self.next_id = 1
        self.pending = {}
        self.stderr_tail = []
        self.reader = asyncio.ensure_future(self._read())
        self.err_reader = asyncio.ensure_future(self._read_err())

    async def _read(self):
        while True:
            line = await self.proc.stdout.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            fut = self.pending.pop(msg.get("id"), None) if "id" in msg and "method" not in msg else None
            if fut is not None and not fut.done():
                fut.set_result(msg)
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError("server closed stdout"))

    async def _read_err(self):
        while True:
            line = await self.proc.stderr.readline()
            if not line:
                break
            self.stderr_tail = (self.stderr_tail + [line.decode(errors="replace").rstrip()])[-20:]

    def _send(self, obj):
        self.proc.stdin.write((json.dumps(obj) + "\n").encode())

    async def request(self, method, params):
        rid = self.next_id
        self.next_id += 1
        fut = asyncio.get_event_loop().create_future()
        self.pending[rid] = fut
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        return await asyncio.wait_for(fut, REPLY_TIMEOUT_S)

    def notify(self, method, params):
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    async def initialize(self):
        r = await self.request("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                              "clientInfo": {"name": "openmail-perf", "version": "0"}})
        self.notify("notifications/initialized", {})
        return r

    async def call(self, name, args):
        """Returns (ok, payload, seconds). On failure payload is {"code": <error code or transport tag>}."""
        t0 = time.perf_counter()
        try:
            r = await self.request("tools/call", {"name": name, "arguments": args})
        except asyncio.TimeoutError:
            return False, {"code": "CLIENT_TIMEOUT"}, time.perf_counter() - t0
        except ConnectionError:
            return False, {"code": "SERVER_CLOSED"}, time.perf_counter() - t0
        dt = time.perf_counter() - t0
        res = r.get("result")
        if res is None:
            return False, {"code": "JSONRPC_ERROR"}, dt
        payload = res.get("structuredContent")
        if payload is None:
            try:
                payload = json.loads(res["content"][0]["text"])
            except (KeyError, IndexError, ValueError, TypeError):
                payload = {}
        if res.get("isError"):
            return False, {"code": (payload.get("error") or {}).get("code", "UNKNOWN")}, dt
        return True, payload, dt


class Sampler:
    """Samples process RSS/threads and simultaneous sessions while a phase runs."""

    def __init__(self, pid, proxy):
        self.pid, self.proxy = pid, proxy
        self.max_rss_kb = 0
        self.max_threads = 0
        self.max_client_side = 0  # ESTABLISHED sockets on the proxy port, kernel view (includes client end)
        self.max_greenmail_side = 0  # ESTABLISHED sockets on GreenMail's published port, kernel view
        self.task = None
        self._stop = False

    async def _run(self):
        while not self._stop:
            st = read_status(self.pid)
            self.max_rss_kb = max(self.max_rss_kb, st.get("VmRSS", 0))
            self.max_threads = max(self.max_threads, st.get("Threads", 0))
            self.max_client_side = max(self.max_client_side, established_on_port(self.proxy.port))
            self.max_greenmail_side = max(self.max_greenmail_side, established_on_port(GM_IMAP_PORT))
            await asyncio.sleep(SAMPLE_INTERVAL_S)

    def start(self):
        self.task = asyncio.ensure_future(self._run())

    async def stop(self):
        self._stop = True
        if self.task:
            await self.task


# ---------------------------------------------------------------- environment helpers
def docker(*args, check=True):
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True)


def api_up():
    import urllib.request
    try:
        urllib.request.urlopen("http://127.0.0.1:%d/api/user" % GM_API_PORT, timeout=2).read()
        return True
    except OSError:
        return False


def gm_ready(timeout=60.0):
    import socket
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < timeout:
        try:
            s = socket.create_connection(("127.0.0.1", GM_IMAP_PORT), 1)
            ok = s.recv(64).startswith(b"* OK")
            s.close()
            if ok and api_up():
                return time.perf_counter() - t0
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError("GreenMail IMAP not ready")


def gm_users_present(n):
    import urllib.request
    try:
        data = json.loads(urllib.request.urlopen("http://127.0.0.1:%d/api/user" % GM_API_PORT, timeout=3).read())
        return len(data) >= n
    except (OSError, ValueError):
        return False


def restore_users(n):
    """Recreates users after a GreenMail restart. The REST API comes up slightly after IMAP, so
    the first call is retried until it answers; that wait is part of the measured recovery."""
    import urllib.error
    import urllib.request
    deadline = time.perf_counter() + 60
    for i in range(n):
        body = json.dumps({"login": user_name(i), "email": "%s@openmail.test" % user_name(i),
                           "password": password(i)}).encode()
        while True:
            req = urllib.request.Request("http://127.0.0.1:%d/api/user" % GM_API_PORT, data=body,
                                         headers={"content-type": "application/json"}, method="POST")
            try:
                urllib.request.urlopen(req, timeout=10).read()
                break
            except urllib.error.HTTPError as e:
                if b"already exists" in e.read():
                    break
                raise
            except OSError:
                if time.perf_counter() > deadline:
                    raise
                time.sleep(0.1)


def write_config(path, n, proxy_port, global_cap):
    lines = ["version = 1", "", "[limits]", "max_global_connections = %d" % global_cap, ""]
    for i in range(n):
        lines += ["[[account]]", 'id = "%s"' % user_name(i), 'display_name = "%s"' % user_name(i),
                  'email = "%s@openmail.test"' % user_name(i), 'auth = "password"',
                  'username = "%s"' % user_name(i),
                  'credential = { kind = "env", var = "PERF_PW_%03d" }' % i,
                  'imap = { host = "localhost", port = %d, tls = "implicit" }' % proxy_port, ""]
    path.write_text("\n".join(lines))


# ---------------------------------------------------------------- one scale point
async def spawn(binary, cfg, ca_pem, n):
    env = {"PATH": os.environ.get("PATH", ""), "SSL_CERT_FILE": str(ca_pem)}
    for i in range(n):
        env["PERF_PW_%03d" % i] = password(i)
    t0 = time.perf_counter()
    proc = await asyncio.create_subprocess_exec(
        binary, "--config", str(cfg), "--log", os.environ.get("PERF_LOG", "warn"), "serve", "--transport", "stdio",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
    mcp = Mcp(proc)
    await mcp.initialize()
    return proc, mcp, time.perf_counter() - t0


async def run_scale(binary, n, messages, ca_pem, cert, key, work, global_cap, do_recovery):
    res = {"accounts": n, "messages_per_account": messages, "global_cap": global_cap}
    proxy = TlsProxy(cert, key, GM_IMAP_PORT)
    await proxy.start()
    cfg = work / ("config-%d.toml" % n)
    write_config(cfg, n, proxy.port, global_cap)
    proc, mcp, startup = await spawn(binary, cfg, ca_pem, n)
    pid = proc.pid
    res["startup_to_initialize_ms"] = ms(startup)
    res["sessions_opened_by_startup"] = proxy.accepted
    await asyncio.sleep(IDLE_SETTLE_S)
    st = read_status(pid)
    res["idle_rss_untouched_mib"] = round(st.get("VmRSS", 0) / 1024.0, 1)
    res["idle_threads_untouched"] = st.get("Threads")

    # -- cold connection establishment: first tool call per account (TCP + TLS + LOGIN + LIST) --
    cold = []
    cold_fail = 0
    for i in range(n):
        ok, _, dt = await mcp.call("mail_list_folders", {"account": user_name(i)})
        if ok:
            cold.append(dt)
        else:
            cold_fail += 1
    res["cold_connect"] = {"samples": len(cold), "failed": cold_fail, "p50_ms": ms(pct(cold, 50)),
                           "p95_ms": ms(pct(cold, 95)), "max_ms": ms(max(cold) if cold else None)}
    await asyncio.sleep(IDLE_SETTLE_S)
    st = read_status(pid)
    res["idle_rss_after_all_accounts_mib"] = round(st.get("VmRSS", 0) / 1024.0, 1)
    res["idle_sessions_after_all_accounts"] = proxy.open

    # -- refs for get_message (one list call per account, 50 newest) --
    refs = {}
    for i in range(n):
        ok, p, _ = await mcp.call("mail_list_messages", {"account": user_name(i), "folder": "INBOX", "limit": 50})
        if ok and p and p.get("messages"):
            refs[i] = [m["message_ref"] for m in p["messages"]]
    res["accounts_with_refs"] = len(refs)

    # -- serial search latency (one request at a time), correctness asserted --
    expected = messages // KEYWORD_EVERY
    lat, wrong, fails = [], 0, 0
    for k in range(SERIAL_SEARCHES):
        i = k % n
        ok, p, dt = await mcp.call("mail_search_messages", {"account": user_name(i), "folder": "INBOX",
                                                            "text": KEYWORD, "limit": 50})
        if not ok:
            fails += 1
            continue
        lat.append(dt)
        if len(p.get("messages", [])) != min(expected, 50):
            wrong += 1
    res["search_serial"] = {"samples": len(lat), "failed": fails, "wrong_hit_count": wrong,
                            "expected_hits": min(expected, 50), "p50_ms": ms(pct(lat, 50)),
                            "p95_ms": ms(pct(lat, 95)), "max_ms": ms(max(lat) if lat else None)}

    res["greenmail_floor"] = await asyncio.get_event_loop().run_in_executor(None, direct_imap_floor)

    # -- concurrent mixed load across all accounts (starts with full rate-limit buckets) --
    await asyncio.sleep(BUCKET_REFILL_S)
    proxy.reset_peak()
    sampler = Sampler(pid, proxy)
    sampler.start()
    sem = asyncio.Semaphore(CONCURRENCY)
    rng = random.Random(1234 + n)
    s_lat, g_lat, errs, msgs_ret = [], [], 0, 0
    err_codes = {}
    wrong_hits = 0
    ticks0, t0 = cpu_ticks(pid), time.perf_counter()

    async def one(kind, i):
        nonlocal errs, msgs_ret, wrong_hits
        async with sem:
            if kind == "search":
                ok, p, dt = await mcp.call("mail_search_messages", {"account": user_name(i), "folder": "INBOX",
                                                                    "text": KEYWORD, "limit": 50})
                if ok:
                    s_lat.append(dt)
                    got = len(p.get("messages", []))
                    msgs_ret += got
                    wrong_hits += got != min(expected, 50)
                else:
                    errs += 1
                    err_codes[p["code"]] = err_codes.get(p["code"], 0) + 1
            else:
                ref = rng.choice(refs[i]) if i in refs else None
                if ref is None:
                    errs += 1
                    return
                ok, p, dt = await mcp.call("mail_get_message", {"message_ref": ref})
                if ok:
                    g_lat.append(dt)
                    msgs_ret += 1
                else:
                    errs += 1
                    err_codes[p["code"]] = err_codes.get(p["code"], 0) + 1

    jobs = [one("search" if rng.random() < 0.5 else "get", rng.randrange(n)) for _ in range(LOAD_REQUESTS)]
    await asyncio.gather(*jobs)
    wall = time.perf_counter() - t0
    cpu_s = (cpu_ticks(pid) - ticks0) / CLK_TCK
    await sampler.stop()
    st = read_status(pid)
    res["load"] = {
        "concurrency": CONCURRENCY, "requests": LOAD_REQUESTS, "errors": errs, "error_codes": err_codes, "wrong_hit_count": wrong_hits,
        "wall_s": round(wall, 2), "requests_per_s": round((len(s_lat) + len(g_lat)) / wall, 1),
        "messages_returned_per_s": round(msgs_ret / wall, 1),
        "search_p50_ms": ms(pct(s_lat, 50)), "search_p95_ms": ms(pct(s_lat, 95)),
        "get_message_p50_ms": ms(pct(g_lat, 50)), "get_message_p95_ms": ms(pct(g_lat, 95)),
        "cpu_seconds": round(cpu_s, 2), "cpu_percent_of_one_core": round(100.0 * cpu_s / wall, 1),
        "peak_rss_mib_sampled": round(sampler.max_rss_kb / 1024.0, 1),
        "peak_rss_mib_vmhwm": round(st.get("VmHWM", 0) / 1024.0, 1),
        "peak_threads": sampler.max_threads,
        "peak_sessions_proxy": proxy.peak,
        "peak_sessions_kernel_proxy_port": sampler.max_client_side,
        "peak_sessions_kernel_greenmail_port": sampler.max_greenmail_side,
        "sessions_accepted_during_load": proxy.accepted,
    }

    # -- burst: one search to EVERY account at once (n in flight) -> worst case for the global cap --
    await asyncio.sleep(BUCKET_REFILL_S)
    proxy.reset_peak()
    sampler = Sampler(pid, proxy)
    sampler.start()
    t0 = time.perf_counter()
    outs = await asyncio.gather(*[mcp.call("mail_search_messages", {"account": user_name(i), "folder": "INBOX",
                                                                    "text": KEYWORD, "limit": 50})
                                  for i in range(n)])
    burst_wall = time.perf_counter() - t0
    await sampler.stop()
    res["burst_all_accounts"] = {
        "in_flight": n, "ok": sum(1 for o in outs if o[0]),
        "error_codes": sorted({o[1]["code"] for o in outs if not o[0]}), "wall_s": round(burst_wall, 2),
        "peak_sessions_proxy": proxy.peak, "peak_sessions_kernel_greenmail_port": sampler.max_greenmail_side,
        "peak_rss_mib_sampled": round(sampler.max_rss_kb / 1024.0, 1)}

    # -- rate-limit probe: sustained throughput ceiling set by the server's own limiter --
    await asyncio.sleep(BUCKET_REFILL_S)
    res["rate_limit_probe"] = await rate_limit_probe(mcp, n)

    # -- recovery: kill GreenMail mid-run, restart, restore users, time until a call succeeds again --
    if do_recovery:
        res["recovery"] = await recovery(mcp, proc, n)

    # -- shutdown on stdin EOF --
    t0 = time.perf_counter()
    proc.stdin.close()
    try:
        rc = await asyncio.wait_for(proc.wait(), 15)
    except asyncio.TimeoutError:
        proc.kill()
        rc = "killed (did not exit within 15 s of stdin EOF)"
        await proc.wait()
    res["shutdown"] = {"exit": rc, "ms": ms(time.perf_counter() - t0)}
    res["stderr_tail"] = mcp.stderr_tail[-5:]
    proxy.server.close()
    return res


def direct_imap_floor():
    """What GreenMail alone costs for the same search, via imaplib straight to its plain port
    (no TLS, no proxy, no OpenMail): the floor under the serial search latency above."""
    import imaplib
    imap = imaplib.IMAP4("127.0.0.1", GM_IMAP_PORT)
    imap.login(user_name(0), password(0))
    imap.select("INBOX", readonly=True)
    lat = []
    for _ in range(30):
        t0 = time.perf_counter()
        imap.search(None, "TEXT", KEYWORD)
        lat.append(time.perf_counter() - t0)
    imap.logout()
    return {"samples": len(lat), "search_text_p50_ms": ms(pct(lat, 50)), "search_text_p95_ms": ms(pct(lat, 95))}


async def rate_limit_probe(mcp, n):
    """PROBE_REQUESTS list_folders calls as fast as the server answers, spread over all accounts."""
    t0 = time.perf_counter()
    outs = await asyncio.gather(*[mcp.call("mail_list_folders", {"account": user_name(k % n)})
                                  for k in range(PROBE_REQUESTS)])
    wall = time.perf_counter() - t0
    ok = sum(1 for o in outs if o[0])
    codes = {}
    for o in outs:
        if not o[0]:
            codes[o[1]["code"]] = codes.get(o[1]["code"], 0) + 1
    return {"requests": PROBE_REQUESTS, "ok": ok, "error_codes": codes, "wall_s": round(wall, 2),
            "ok_per_s": round(ok / wall, 1)}


async def recovery(mcp, proc, n):
    """Background searches run continuously while GreenMail is killed (SIGKILL) and restarted."""
    out = {}
    stop = False
    log = []  # (t_end, ok, seconds)

    async def worker(w):
        k = w
        while not stop:
            i = k % n
            k += 4
            ok, _, dt = await mcp.call("mail_search_messages", {"account": user_name(i), "folder": "INBOX",
                                                                "text": KEYWORD, "limit": 5})
            log.append((time.perf_counter(), ok, dt))
            await asyncio.sleep(RECOVERY_PACE_S)

    workers = [asyncio.ensure_future(worker(w)) for w in range(4)]
    await asyncio.sleep(3.0)
    t_kill = time.perf_counter()
    await asyncio.get_event_loop().run_in_executor(None, lambda: docker("kill", CONTAINER))
    await asyncio.sleep(1.0)
    await asyncio.get_event_loop().run_in_executor(None, lambda: docker("start", CONTAINER))
    up = await asyncio.get_event_loop().run_in_executor(None, gm_ready)
    t_port = time.perf_counter()
    # GreenMail keeps mail and users in memory only: a restart is a fresh, empty server. Users are
    # recreated through the REST API (empty INBOXes), which is what a real operator restart implies.
    await asyncio.get_event_loop().run_in_executor(None, lambda: restore_users(n))
    t_users = time.perf_counter()
    first_ok = None
    deadline = time.perf_counter() + 60
    while time.perf_counter() < deadline and first_ok is None:
        after = [e for e in log if e[0] > t_users and e[1]]
        if after:
            first_ok = min(e[0] for e in after)
        else:
            await asyncio.sleep(0.05)
    stop = True
    await asyncio.gather(*workers)
    failed_during = [e for e in log if t_kill <= e[0] and not e[1]]
    out["process_survived"] = proc.returncode is None
    out["greenmail_port_ready_after_start_s"] = round(up, 2)
    out["kill_to_port_ready_s"] = round(t_port - t_kill, 2)
    out["users_restored_after_port_ready_s"] = round(t_users - t_port, 2)
    out["recovery_after_server_ready_s"] = None if first_ok is None else round(first_ok - t_users, 2)
    out["kill_to_first_success_s"] = None if first_ok is None else round(first_ok - t_kill, 2)
    out["failed_calls_during_outage"] = len(failed_during)
    out["slowest_failed_call_s"] = round(max((e[2] for e in failed_during), default=0.0), 2)
    return out


# ---------------------------------------------------------------- orchestration
def check_budgets(results, budgets_path):
    budgets = json.loads(Path(budgets_path).read_text())
    problems = []
    for r in results:
        b = budgets.get(str(r["accounts"]))
        if not b:
            continue
        got = {
            "startup_to_initialize_ms": r["startup_to_initialize_ms"],
            "idle_rss_after_all_accounts_mib": r["idle_rss_after_all_accounts_mib"],
            "peak_rss_mib_vmhwm": r["load"]["peak_rss_mib_vmhwm"],
            "search_serial_p95_ms": r["search_serial"]["p95_ms"],
            "load_search_p95_ms": r["load"]["search_p95_ms"],
            "peak_sessions": max(r["load"]["peak_sessions_proxy"], r["burst_all_accounts"]["peak_sessions_proxy"]),
        }
        for k, limit in b.items():
            if got.get(k) is None or got[k] > limit:
                problems.append("N=%s %s = %s exceeds budget %s" % (r["accounts"], k, got.get(k), limit))
    return problems


def derive_budgets(results, headroom):
    """Budget = measured baseline x headroom (rounded up); the session cap is the configured cap."""
    out = {}
    up = lambda v: int(-(-v * headroom // 1)) if v is not None else None
    for r in results:
        out[str(r["accounts"])] = {
            "startup_to_initialize_ms": up(r["startup_to_initialize_ms"]),
            "idle_rss_after_all_accounts_mib": up(r["idle_rss_after_all_accounts_mib"]),
            "peak_rss_mib_vmhwm": up(r["load"]["peak_rss_mib_vmhwm"]),
            "search_serial_p95_ms": up(r["search_serial"]["p95_ms"]),
            "load_search_p95_ms": up(r["load"]["search_p95_ms"]),
            "peak_sessions": r["global_cap"],
        }
    return out


async def main_async(a):
    work = Path(tempfile.mkdtemp(prefix="openmail-perf-"))
    try:
        ca_pem, cert, key = make_pki(work / "pki")
        scales = [int(x) for x in a.accounts.split(",")]
        biggest = max(scales)
        if a.compose_up:
            subprocess.run(["docker", "compose", "-f", str(COMPOSE_PERF), "up", "-d", "--force-recreate"],
                           check=True, capture_output=True)
        gm_ready()
        t0 = time.perf_counter()
        subprocess.run([sys.executable, str(PROVISION), str(biggest), str(a.messages)], check=True)
        provision_s = time.perf_counter() - t0
        results = []
        dirty = False  # a recovery phase leaves GreenMail restarted, i.e. empty
        for n in scales:
            if dirty:
                subprocess.run([sys.executable, str(PROVISION), str(biggest), str(a.messages)], check=True)
            print("== N=%d accounts ==" % n, file=sys.stderr)
            r = await run_scale(a.bin, n, a.messages, ca_pem, cert, key, work, a.global_cap, not a.no_recovery)
            results.append(r)
            dirty = not a.no_recovery
            print(json.dumps(r), file=sys.stderr)
        meta = {"provision_seconds_for_max": round(provision_s, 1), "binary": a.bin,
                "binary_bytes": os.stat(a.bin).st_size, "messages_per_account": a.messages,
                "body_bytes_avg": 2238, "greenmail_image": "greenmail/standalone@sha256:d6db42a4 (2.1.3)",
                "host": "docker bridge via userland proxy, TLS terminated by python asyncio proxy"}
        doc = {"meta": meta, "results": results}
        Path(a.out).write_text(json.dumps(doc, indent=2))
        if a.write_budgets:
            Path(a.write_budgets).write_text(json.dumps(derive_budgets(results, a.headroom), indent=2) + "\n")
        if a.check_budgets:
            problems = check_budgets(results, a.check_budgets)
            for p in problems:
                print("BUDGET EXCEEDED: " + p, file=sys.stderr)
            return 1 if problems else 0
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bin", required=True)
    p.add_argument("--accounts", default="1,10,50,100")
    p.add_argument("--messages", type=int, default=200)
    p.add_argument("--global-cap", type=int, default=8)
    p.add_argument("--out", required=True)
    p.add_argument("--no-recovery", action="store_true")
    p.add_argument("--compose-up", action="store_true", help="(re)create the perf GreenMail container first")
    p.add_argument("--write-budgets")
    p.add_argument("--headroom", type=float, default=1.5)
    p.add_argument("--check-budgets")
    a = p.parse_args()
    sys.exit(asyncio.get_event_loop().run_until_complete(main_async(a)))


if __name__ == "__main__":
    main()
