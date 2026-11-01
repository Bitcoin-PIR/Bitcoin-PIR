#!/usr/bin/env python3
"""Memory and speed test of PRs #466 and #467 against main.

Started by run.sh; can also be run alone:

  python3 bench.py --config DATA/databases.toml --client BENCH_CLIENT \
      --build main=PATH/unified_server --build pr=PATH/unified_server --out DIR

For each build it starts a DPF pair (two `--role secondary --serve-queries`
servers on one machine) and then one OnionPIR server (`--role primary
--serve-queries`), runs the client against them with a cold page cache
(`sudo -n purge`) and a warm one, and samples each server's memory. It writes
results.json and report.md to --out. Python 3.9+, standard library only.
"""

import argparse
import datetime
import json
import os
import platform
import re
import signal
import subprocess
import sys
import threading
import time

MAC = platform.system() == "Darwin"
GB = 1024 ** 3

DPF_RUNS = [("cold_1", 1, True), ("warm_1", 1, False), ("cold_4", 4, True), ("warm_4", 4, False)]
ONION_RUNS = [("cold_1", 1, True), ("warm_1", 1, False)]


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


# ---------------------------------------------------------------- memory

_UNITS = {"": 1, "B": 1, "K": 1024, "KB": 1024, "M": 1024 ** 2, "MB": 1024 ** 2,
          "G": GB, "GB": GB, "T": 1024 ** 4, "TB": 1024 ** 4}


def _size(text):
    m = re.match(r"\s*([0-9.]+)\s*([KMGT]?B?)\s*$", text.strip(), re.I)
    if not m:
        return None
    return int(float(m.group(1)) * _UNITS[m.group(2).upper()])


def footprint(pid):
    """(current, peak) physical footprint in bytes: the memory the process
    itself needs, without clean file pages (page cache of its mmaps).
    macOS: vmmap --summary. Elsewhere: (RSS, None) as a stand-in."""
    if MAC:
        try:
            out = subprocess.run(["vmmap", "--summary", str(pid)], capture_output=True,
                                 text=True, timeout=60).stdout
        except Exception:
            out = ""
        cur = re.search(r"^Physical footprint:\s*(\S+)", out, re.M)
        peak = re.search(r"^Physical footprint \(peak\):\s*(\S+)", out, re.M)
        if cur:
            return _size(cur.group(1)), _size(peak.group(1)) if peak else None
        return None, None
    return rss(pid), None


def rss(pid):
    """Resident set size in bytes (includes the page cache of mapped files)."""
    try:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=10).stdout.strip()
        return int(out) * 1024 if out else None
    except Exception:
        return None


class Sampler(threading.Thread):
    """Samples the RSS of the given pids every `every` seconds, tagging each
    sample with the current phase. Footprint is read only between runs:
    vmmap suspends the process while it inspects it."""

    def __init__(self, pids, every=1.0):
        super().__init__(daemon=True)
        self.pids, self.every, self.phase = pids, every, "startup"
        self.samples = []  # (t, phase, name, rss)
        self.stop = threading.Event()

    def run(self):
        while not self.stop.is_set():
            for name, pid in self.pids.items():
                self.samples.append((time.time(), self.phase, name, rss(pid)))
            self.stop.wait(self.every)

    def peak_rss(self, name, phase):
        vals = [s[3] for s in self.samples if s[2] == name and s[1] == phase and s[3]]
        return max(vals) if vals else None


# ---------------------------------------------------------------- servers

class Server:
    def __init__(self, name, binary, config, port, role_flags, logdir, label):
        self.name, self.port = name, port
        self.logpath = os.path.join(logdir, "%s-%s.log" % (label, name))
        cmd = [binary, "--bind-address", "127.0.0.1", "--port", str(port), "--config", config,
               "--connection-idle-timeout-ms", "3600000"] + role_flags
        if os.path.exists("/usr/bin/time"):
            cmd = ["/usr/bin/time", "-l" if MAC else "-v"] + cmd
        self.logf = open(self.logpath, "w")
        self.proc = subprocess.Popen(cmd, stdout=self.logf, stderr=subprocess.STDOUT)
        self.pid = self._server_pid()
        self.started = time.time()

    def _server_pid(self):
        if os.path.basename(self.proc.args[0]) != "time":
            return self.proc.pid
        for _ in range(100):
            out = subprocess.run(["pgrep", "-P", str(self.proc.pid)], capture_output=True,
                                 text=True).stdout.split()
            if out:
                return int(out[0])
            time.sleep(0.1)
        raise RuntimeError("could not find the server process under /usr/bin/time")

    def wait_listening(self, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("%s exited during startup; see %s" % (self.name, self.logpath))
            with open(self.logpath, errors="replace") as f:
                if "Listening on" in f.read():
                    return time.time() - self.started
            time.sleep(1)
        raise RuntimeError("%s not listening after %ds; see %s" % (self.name, timeout, self.logpath))

    def stop(self):
        """SIGINT, then the lifetime peaks /usr/bin/time printed."""
        try:
            os.kill(self.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            os.kill(self.pid, signal.SIGKILL)
            self.proc.wait()
        self.logf.close()
        with open(self.logpath, errors="replace") as f:
            text = f.read()
        out = {}
        m = re.search(r"(\d+)\s+maximum resident set size", text)  # macOS, bytes
        if m:
            out["max_rss"] = int(m.group(1))
        m = re.search(r"(\d+)\s+peak memory footprint", text)  # macOS 13+, bytes
        if m:
            out["peak_footprint"] = int(m.group(1))
        m = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", text)  # GNU time
        if m:
            out["max_rss"] = int(m.group(1)) * 1024
        return out


def purge_works():
    if MAC:
        return subprocess.run(["sudo", "-n", "/usr/sbin/purge"], capture_output=True).returncode == 0
    return subprocess.run(["sudo", "-n", "sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"],
                          capture_output=True).returncode == 0


def purge():
    if MAC:
        subprocess.run(["sudo", "-n", "/usr/sbin/purge"], check=True)
    else:
        subprocess.run(["sudo", "-n", "sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"],
                       check=True)


def run_client(client, args, timeout):
    t = time.time()
    p = subprocess.run([client] + args, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        return {"error": "client exit %d: %s" % (p.returncode, p.stderr[-2000:]),
                "elapsed_s": time.time() - t}
    try:
        out = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception as e:
        return {"error": "client output: %s: %s" % (e, p.stdout[-2000:])}
    times = [c.get("full_sync_s", 0) + (c.get("delta_sync_s") or 0) for c in out["clients"]]
    out["query_wall_s"] = max(times) if times else None
    return out


def phase(label, binary, args, kind, can_purge):
    """One server set (DPF pair or OnionPIR) for one build."""
    logdir = os.path.join(args.out, "logs")
    if kind == "dpf":
        servers = [Server("dpf0", binary, args.config, 18091, ["--role", "secondary", "--serve-queries"], logdir, label),
                   Server("dpf1", binary, args.config, 18092, ["--role", "secondary", "--serve-queries"], logdir, label)]
        client_args = ["dpf", "ws://127.0.0.1:18091", "ws://127.0.0.1:18092"]
        runs, measured = DPF_RUNS, "dpf1"
    else:
        servers = [Server("onion", binary, args.config, 18093, ["--role", "primary", "--serve-queries"], logdir, label)]
        client_args = ["onion", "ws://127.0.0.1:18093"]
        runs, measured = ONION_RUNS, "onion"
    sampler = Sampler({s.name: s.pid for s in servers})
    sampler.start()
    res = {"runs": {}}
    try:
        res["startup_s"] = max(s.wait_listening(args.startup_timeout) for s in servers)
        msrv = [s for s in servers if s.name == measured][0]
        res["after_startup_footprint"], res["startup_peak_footprint"] = footprint(msrv.pid)
        res["startup_peak_rss_sampled"] = sampler.peak_rss(measured, "startup")
        log("%s %s: listening after %.0fs" % (label, kind, res["startup_s"]))
        for name, conc, cold in runs:
            if cold and not can_purge:
                res["runs"][name] = {"skipped": "purge needs sudo without a password"}
                continue
            if cold:
                purge()
            sampler.phase = name
            log("%s %s: %s ..." % (label, kind, name))
            r = run_client(args.client, client_args + ["--concurrency", str(conc)], args.query_timeout)
            cur, peak = footprint(msrv.pid)
            r["footprint_after"], r["lifetime_peak_footprint_after"] = cur, peak
            r["peak_rss_sampled"] = sampler.peak_rss(measured, name)
            res["runs"][name] = r
            log("%s %s: %s took %s s%s" % (label, kind, name, _fmt(r.get("query_wall_s")),
                                          "  ERROR " + r["error"][:200] if "error" in r else ""))
    except Exception as e:
        res["error"] = str(e)
        log("%s %s: ERROR %s" % (label, kind, e))
    finally:
        sampler.stop.set()
        sampler.join(timeout=120)
        for s in servers:
            res.setdefault("time_l", {})[s.name] = s.stop()
        res["samples"] = sampler.samples
    return res


# ---------------------------------------------------------------- report

def _fmt(v, nd=1):
    return "—" if v is None else ("%.*f" % (nd, v))


def _gb(v):
    return "—" if not v else "%.2f GB" % (v / GB)


def strip_timings(run):
    """What must match between builds: decoded results, not timings."""
    if not isinstance(run, dict) or "clients" not in run:
        return None
    return [{"full": c.get("full"), "delta": c.get("delta"), "error": c.get("error")}
            for c in run["clients"]]


def problems(run):
    out = []
    for c in run.get("clients", []):
        if "error" in c:
            out.append(c["error"])
        for key in ("full", "delta"):
            part = c.get(key) or {}
            if "error" in part:
                out.append("%s: %s" % (key, part["error"]))
            for r in part.get("results", []):
                if r["result"] is not None and not r["result"].get("merkle_verified"):
                    out.append("%s %s: merkle_verified=false" % (key, r["address"]))
    return out


def machine():
    info = {"platform": platform.platform()}
    if MAC:
        for key in ("hw.memsize", "machdep.cpu.brand_string", "hw.ncpu"):
            info[key] = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True).stdout.strip()
    return info


def report(results, path):
    builds = list(results["builds"].keys())
    base = builds[0]
    L = []
    L.append("# PR #466 / #467 实测报告\n")
    L.append("生成时间 %s。机器：%s。" % (results["finished"], json.dumps(results["machine"], ensure_ascii=False)))
    L.append("清页缓存（purge）：%s。\n" % ("可用" if results["purge"] else "不可用，冷缓存的几轮跳过了"))
    for b in builds:
        L.append("- %s：%s" % (b, results["revs"].get(b, "")))
    L.append("")

    L.append("## 1. 结果是否一致（和 %s 比）\n" % base)
    L.append("| 构建 | 后端 | 轮次 | 和基线一致 | 问题 |")
    L.append("| --- | --- | --- | --- | --- |")
    for b in builds:
        for kind in ("dpf", "onion"):
            ph = results["builds"][b].get(kind)
            if not ph:
                continue
            if "error" in ph:
                L.append("| %s | %s | — | — | **出错**：%s |" % (b, kind, ph["error"][:300]))
            for name, run in ph["runs"].items():
                if "skipped" in run:
                    continue
                ref = results["builds"][base][kind]["runs"].get(name)
                same = "—" if b == base else ("是" if strip_timings(run) == strip_timings(ref) else "**否**")
                probs = problems(run) + ([run["error"]] if "error" in run else [])
                L.append("| %s | %s | %s | %s | %s |" % (b, kind, name, same, "; ".join(probs)[:300] or "无"))
    L.append("")

    L.append("## 1b. OnionPIR 和 DPF 的结果是否一致（同一构建、warm_1，完整快照）\n")
    L.append("| 构建 | 地址 | DPF | OnionPIR | 一致 |")
    L.append("| --- | --- | --- | --- | --- |")
    for b in builds:
        try:
            d = results["builds"][b]["dpf"]["runs"]["warm_1"]["clients"][0]["full"]["results"]
            o = results["builds"][b]["onion"]["runs"]["warm_1"]["clients"][0]["full"]["results"]
        except (KeyError, IndexError, TypeError):
            continue
        for dr, orr in zip(d, o):
            def show(r):
                r = r["result"]
                if r is None:
                    return "未找到"
                return "whale" if r["is_whale"] else "%d 条" % len(r["entries"])
            same = (dr["result"] or {}).get("entries") == (orr["result"] or {}).get("entries") and \
                (dr["result"] or {}).get("is_whale") == (orr["result"] or {}).get("is_whale")
            L.append("| %s | %s | %s | %s | %s |" % (b, dr["address"], show(dr), show(orr), "是" if same else "**否**"))
    L.append("")

    L.append("## 2. 内存（被测节点：DPF 取 server 1，OnionPIR 取唯一一台）\n")
    L.append("footprint 是进程自己必须占的内存（不含 mmap 文件的页缓存），决定机器最少要多大内存；RSS 含页缓存，只作参考。\n")
    L.append("| 构建 | 节点 | 启动耗时 | 启动后 footprint | 启动峰值 footprint | 全程峰值 footprint | 全程最大 RSS |")
    L.append("| --- | --- | --- | --- | --- | --- | --- |")
    for b in builds:
        for kind, srv in (("dpf", "dpf1"), ("onion", "onion")):
            ph = results["builds"][b].get(kind)
            if not ph:
                continue
            tl = ph.get("time_l", {}).get(srv, {})
            L.append("| %s | %s | %s s | %s | %s | %s | %s |" % (
                b, kind, _fmt(ph.get("startup_s"), 0), _gb(ph.get("after_startup_footprint")),
                _gb(ph.get("startup_peak_footprint")),
                _gb(tl.get("peak_footprint")), _gb(tl.get("max_rss"))))
    L.append("")

    L.append("## 3. 速度（秒，所有并发客户端里最慢的那个：完整快照查询 + delta 查询）\n")
    L.append("cold = 每轮前清页缓存，接近小内存机器每次都要从磁盘读表的情况；warm = 表已在页缓存里。")
    L.append("DPF 的 4 并发轮次看 #467 的共享扫描效果：4 个客户端同时查，各查一个地址。\n")
    L.append("| 构建 | 后端 | 轮次 | 耗时 | 到这一轮为止的峰值 footprint | 这一轮最大 RSS |")
    L.append("| --- | --- | --- | --- | --- | --- |")
    for kind in ("dpf", "onion"):
        for b in builds:
            ph = results["builds"][b].get(kind)
            if not ph:
                continue
            for name, run in ph["runs"].items():
                if "skipped" in run:
                    L.append("| %s | %s | %s | 跳过 | | |" % (b, kind, name))
                    continue
                L.append("| %s | %s | %s | %s | %s | %s |" % (
                    b, kind, name, _fmt(run.get("query_wall_s")),
                    _gb(run.get("lifetime_peak_footprint_after")), _gb(run.get("peak_rss_sampled"))))
    L.append("")
    L.append("原始数据（每个客户端的分步耗时、每秒的 RSS 采样）在 results.json，服务端日志在 logs/。")
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="databases.toml of the downloaded generation")
    ap.add_argument("--client", required=True, help="bench_client binary")
    ap.add_argument("--build", action="append", required=True, metavar="LABEL=BINARY",
                    help="first one is the baseline")
    ap.add_argument("--rev", action="append", default=[], metavar="LABEL=TEXT")
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", choices=["dpf", "onion"])
    ap.add_argument("--startup-timeout", type=int, default=3600)
    ap.add_argument("--query-timeout", type=int, default=3600)
    args = ap.parse_args()
    os.makedirs(os.path.join(args.out, "logs"), exist_ok=True)

    can_purge = purge_works()
    if not can_purge:
        log("WARNING: `sudo -n purge` failed, so the cold-cache runs are skipped. "
            "See README for the one-line sudoers entry that enables it.")
    results = {"machine": machine(), "purge": can_purge, "builds": {},
               "revs": dict(r.split("=", 1) for r in args.rev),
               "started": datetime.datetime.now().isoformat(timespec="seconds")}
    for spec in args.build:
        label, binary = spec.split("=", 1)
        results["builds"][label] = {}
        for kind in ("dpf", "onion"):
            if args.only and args.only != kind:
                continue
            results["builds"][label][kind] = phase(label, binary, args, kind, can_purge)
            with open(os.path.join(args.out, "results.json"), "w") as f:
                json.dump(results, f, indent=1)
    results["finished"] = datetime.datetime.now().isoformat(timespec="seconds")
    with open(os.path.join(args.out, "results.json"), "w") as f:
        json.dump(results, f, indent=1)
    report(results, os.path.join(args.out, "report.md"))
    log("done: %s" % os.path.join(args.out, "report.md"))


if __name__ == "__main__":
    sys.exit(main())
