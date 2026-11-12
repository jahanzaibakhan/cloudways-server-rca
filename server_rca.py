#!/usr/bin/env python3
"""
Cloudways Server RCA Investigator
=================================

Asks for a From / To date, then runs a read-only root cause analysis of the
server for that window: OOM kills, reboots, service crashes, CPU / memory
history (atop), configuration red flags, PHP-FPM, MySQL/MariaDB and traffic.
It ends with the top culprits, optimizations, an upscale decision, a one-line
verdict and a customer-shareable paragraph.

Usage (interactive - asks for the window):
  curl -sS https://raw.githubusercontent.com/jahanzaibakhan/cloudways-server-rca/main/server_rca.py | python3 -

Usage (non-interactive):
  python3 server_rca.py --from "2026-11-05" --to "2026-11-12 10:00"
  python3 server_rca.py --last 7d

Safety: read-only. It never restarts, kills or reconfigures anything, runs
every subprocess with a timeout, masks SQL literals and never prints
credentials. The only file it can write is the optional --save / --json report.
All times are server local time.
"""
import argparse
import glob
import gzip
import html
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta

VERSION = "1.2.0"
WIDTH = 100

# ----------------------------------------------------------------------------
# Constants and patterns
# ----------------------------------------------------------------------------
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
PAGE_KB = (os.sysconf("SC_PAGE_SIZE") // 1024) if hasattr(os, "sysconf") else 4
CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
NCPU = os.cpu_count() or 1
RAM_TIERS_GB = [1, 2, 4, 8, 16, 32, 64, 96, 128, 192, 256, 384]
# Log locations (module-level so tests can point them at fixtures)
SYSLOG_PATTERNS = ("/var/log/syslog*", "/var/log/kern.log*", "/var/log/messages*")
FPM_LOG_GLOB = "/var/log/php*-fpm.log*"
ATOP_DIR = "/var/log/atop"
USE_JOURNAL = True

try:
    LOCAL_OFF_MIN = int((datetime.now().astimezone().utcoffset() or timedelta(0)).total_seconds() // 60)
except (OSError, ValueError):
    LOCAL_OFF_MIN = 0
TZ_NAME = time.strftime("%Z") or "local"

SYSLOG_ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?\s?([+-]\d{2}:?\d{2}|Z)?")
SYSLOG_CLASSIC_RE = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
OOM_KILLED_RE = re.compile(r"Killed process (\d+) \((.+?)\)(?:,|\s+total-vm|\s*$)")
OOM_INVOKED_RE = re.compile(r"(\S+) invoked oom-killer")
OOM_TASK_RE = re.compile(r"\[\s*(\d+)\]\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$")
SD_EXIT_RE = re.compile(r"systemd\[1\]: (\S+?)\.service: Main process exited, code=(\w+), status=(\S+)")
SD_FAIL_RE = re.compile(r"systemd\[1\]: (\S+?)\.service: Failed with result '([^']+)'")
SD_RESTART_RE = re.compile(r"systemd\[1\]: (\S+?)\.service: Scheduled restart job, restart counter is at (\d+)")
SD_OOM_RE = re.compile(r"systemd\[1\]: (\S+?)\.service: A process of this unit has been killed by the OOM killer")
SD_STARTED_RE = re.compile(r"systemd\[1\]: Started (.+?)\.?\s*$")
WATCH_UNIT_RE = re.compile(r"^(nginx|apache2|httpd|mariadb|mysql|mysqld|redis|redis-server|php[\d.]*-fpm|varnish|"
                           r"memcached|elasticsearch|opensearch|supervisor)", re.I)
SVC_KEYWORDS = [
    ("mariadb", re.compile(r"mariadb|mysql", re.I)),
    ("nginx", re.compile(r"nginx|high performance web server", re.I)),
    ("apache2", re.compile(r"apache", re.I)),
    ("redis", re.compile(r"redis|key-value store", re.I)),
    ("php-fpm", re.compile(r"php.*fpm|fastcgi process manager", re.I)),
    ("varnish", re.compile(r"varnish(?!ncsa)", re.I)),
    ("memcached", re.compile(r"memcached", re.I)),
    ("elasticsearch", re.compile(r"elasticsearch|opensearch", re.I)),
]

ACCESS_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}):(\d{2}):\d{2}\s*([+-]\d{4})?\]\s+'
    r'"([A-Z]+)\s+([^\s"]*)[^"]*"\s+(\d{3})\s+\S+(?:\s+"[^"]*"\s+"([^"]*)")?')
# Cloudways FPM access.format:
# %{HTTP_X_FORWARDED_FOR}e - [%t] "%m %r%Q%q" %s %l - %P %p %{seconds}d %{bytes}M %{user}C%% %{system}C%% "%{REQUEST_URI}e"
FPM_ACCESS_RE = re.compile(
    r'^(\S+)\s+\S+\s+\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}):(\d{2}):\d{2}\s*([+-]\d{4})?\]\s+"([A-Z]+)\s+([^"]*)"\s+'
    r'(\d{3})\s+\S+\s+\S+\s+(?:\d+\s+\d+\s+)?(\d+(?:\.\d+)?)\s+(\d+)\s+([\d.]+)%\s+([\d.]+)%\s*(?:"([^"]*)")?')
FPM_LOG_TS_RE = re.compile(r"^\[(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})")
FPM_POOL_RE = re.compile(r"\[pool ([^\]]+)\]")
FPM_MAXCHILD_RE = re.compile(r"server reached (?:pm\.)?max_children setting \((\d+)\)")
FPM_SIGNAL_RE = re.compile(r"child \d+ exited on signal (\d+)")
SLOW_HEADER_RE = re.compile(r"^\[(\d{2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\]\s+\[pool ([^\]]+)\]\s+pid")
SLOW_FRAME_RE = re.compile(r"^\[0x[0-9a-fA-F]+\]\s+(.+?)\(\)\s+(.+?):(\d+)\s*$")
POOL_SUFFIX_RE = re.compile(r"-\d{2}$")
ATOP_PROC_RE = re.compile(r"^(PRC|PRM|PRG) (\S+) (\d+) (\S+) (\S+) (\d+) (\d+) \((.*?)\) (\S) (.*)$")

MY_SLOW_TS_RE = re.compile(r"^SET timestamp=(\d+)")
MY_SLOW_TIME_ISO_RE = re.compile(r"^# Time:\s+(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z)?")
MY_SLOW_TIME_OLD_RE = re.compile(r"^# Time:\s+(\d{2})(\d{2})(\d{2})\s+(\d{1,2}):(\d{2}):(\d{2})")
MY_SLOW_USER_RE = re.compile(r"^# User@Host:\s*([^\[\s]+)")
MY_SLOW_SCHEMA_RE = re.compile(r"Schema:[ \t]*([^\s:]*)(?=\s|$)")
MY_SLOW_QT_RE = re.compile(r"^# Query_time:\s*([\d.]+)\s+Lock_time:\s*([\d.]+)\s+Rows_sent:\s*(\d+)\s+Rows_examined:\s*(\d+)")
MY_SLOW_USE_RE = re.compile(r"^use\s+`?([^`;\s]+)`?;", re.I)
MY_ERR_TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ]\s?(\d{1,2}):(\d{2}):(\d{2})(?:\.\d+)?(Z)?")
SQL_STRING_RE = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")
SQL_NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
SQL_INLIST_RE = re.compile(r"\(\s*\?(?:\s*,\s*\?)+\s*\)")

BOT_UA_MARKERS = ("bot", "crawler", "spider", "slurp", "crawl", "scrapy", "python-requests", "curl/", "wget/",
                  "go-http-client", "httpclient", "java/", "okhttp", "libwww", "headless", "phantomjs",
                  "puppeteer", "playwright", "semrush", "ahrefs", "mj12", "bytespider", "facebookexternalhit",
                  "dataforseo", "barkrowler", "serpstat", "zoominfo", "python-urllib", "aiohttp", "axios",
                  "guzzlehttp", "masscan", "zgrab", "nmap", "nikto", "sqlmap", "wpscan", "nuclei")

# (label, regex on process name). Order matters.
SERVICE_PATTERNS = [
    ("mysql", re.compile(r"^(mysqld|mariadbd|mariadb)")),
    ("redis", re.compile(r"^redis-server")),
    ("memcached", re.compile(r"^memcached")),
    ("varnish", re.compile(r"^(varnishd|cache-main|cache-worker)")),
    ("nginx", re.compile(r"^nginx")),
    ("apache", re.compile(r"^(apache2|httpd)")),
    ("elasticsearch", re.compile(r"^(java|elasticsearch|opensearch)")),
    ("imunify", re.compile(r"^(imunify|i360|aibolit|rustbolit|wafd|php-imunify|clamd|ossec|wazuh|hyperscan)|imunify")),
    ("monitoring", re.compile(r"^(atop|newrelic|nrsysmond|node_exporter|telegraf|monit|netdata|cwmon|sensu|collectd)")),
    ("backup", re.compile(r"^(duplicity|rsync|tar|gzip|pigz|mysqldump|mariadb-dump|xtrabackup|mariabackup)$")),
    ("systemd", re.compile(r"^(systemd|\(sd-pam\)|dbus-daemon|cron|rsyslogd|sshd)")),
]
KERNEL_THREAD_RE = re.compile(r"^(kworker|ksoftirqd|kswapd|kcompactd|khugepaged|migration|rcu_|jbd2|kthreadd|irq/|scsi_|watchdog)")
ROLE = {
    "mysql": "Database - usually the OOM victim (largest single process)",
    "redis": "Object cache (Redis)",
    "memcached": "Object cache (Memcached)",
    "varnish": "Page cache (Varnish)",
    "nginx": "Web server (Nginx)",
    "apache": "Web server (Apache)",
    "elasticsearch": "Search service (Elasticsearch/OpenSearch, Java heap)",
    "imunify": "Security agent (INTERNAL - do not share)",
    "monitoring": "Monitoring agent",
    "backup": "Backup job",
    "systemd": "System process (collateral victim)",
    "php-fpm": "PHP workers (application code)",
    "app": "PHP workers (application code)",
    "other": "Other process",
}
CUSTOMER_NAME = {
    "mysql": "the database service", "redis": "the object cache", "memcached": "the object cache",
    "varnish": "the page cache", "nginx": "the web server", "apache": "the web server",
    "elasticsearch": "the search service (Elasticsearch/OpenSearch)", "imunify": "background system processes",
    "monitoring": "background system processes", "backup": "backup jobs", "systemd": "system processes",
    "php-fpm": "PHP application processes", "other": "background processes",
}
SEV_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
ANSI = {"red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m", "cyan": "\033[96m", "dim": "\033[2m",
        "bold": "\033[1m", "reset": "\033[0m", "key": "\033[36m", "title": "\033[1;96m", "h2": "\033[1;96m",
        "h3": "\033[1;93m", "th": "\033[1;97m", "bar1": "\033[1;97;44m", "bar2": "\033[1;30;42m"}
HL_RE = re.compile(r"\[(?:Confirmed|Likely|Suspected|Unknown)\]|CRITICAL|RESTARTED INSIDE THE WINDOW|NON-ROOT|"
                   r"Needs review|Elevated errors")
HL_COLORS = {"[Confirmed]": "green", "CRITICAL": "red", "RESTARTED INSIDE THE WINDOW": "red"}
CELL_COLORS = {"Normal": "green", "Needs review": "yellow", "Elevated errors": "yellow", "No data": "dim", "YES": "red"}
HOUR_KEY = "%Y-%m-%d %H"


# ----------------------------------------------------------------------------
# Generic helpers
# ----------------------------------------------------------------------------
class Ctx:
    """Run-wide context: options, discovered apps, data-availability notes."""

    def __init__(self, args=None):
        self.args = args
        self.is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        self.notes = []
        self.t0 = time.time()
        self.apps = {}
        self.pools = {}
        self.user_to_app = {}
        self._class_cache = {}

    def progress(self, msg):
        if self.args is None or not getattr(self.args, "quiet", False):
            print("[%6.1fs] %s" % (time.time() - self.t0, msg), file=sys.stderr, flush=True)

    def note(self, msg):
        if msg not in self.notes:
            self.notes.append(msg)


def run_cmd(cmd, timeout=15, env=None):
    """Run a read-only command safely (no shell, timeout, bounded output)."""
    if not os.path.isabs(cmd[0]) and not shutil.which(cmd[0]):
        return 127, "", cmd[0] + " not found"
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                           timeout=timeout, check=False, stdin=subprocess.DEVNULL, errors="replace", env=env)
        return p.returncode, p.stdout[:20000000], p.stderr[:20000]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def stream_cmd(cmd, timeout=120):
    """Yield stdout lines of a read-only command; the process is killed after `timeout` seconds."""
    if not os.path.isabs(cmd[0]) and not shutil.which(cmd[0]):
        return
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                             universal_newlines=True, errors="replace")
    except OSError:
        return
    timer = threading.Timer(timeout, p.kill)
    timer.daemon = True
    timer.start()
    try:
        for line in p.stdout:
            yield line.rstrip("\n")
    finally:
        timer.cancel()
        if p.poll() is None:
            p.kill()
        try:
            p.stdout.close()
        except OSError:
            pass
        p.wait()


def read_text(path, limit=2000000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except (OSError, ValueError):
        return None


def tz_minutes(tz):
    """'+0530', '+05:30' or 'Z' -> offset in minutes."""
    if not tz or tz == "Z":
        return 0
    tz = tz.replace(":", "")
    sign = -1 if tz[0] == "-" else 1
    return sign * (int(tz[1:3]) * 60 + int(tz[3:5]))


def make_ts(y, mon, d, h, mi, s, tz=None):
    """Build a naive server-local datetime; `tz` (if given) is the offset the values are expressed in."""
    month = MONTHS.get(mon[:1].upper() + mon[1:3].lower()) if isinstance(mon, str) and not mon.isdigit() else int(mon)
    if not month:
        return None
    try:
        ts = datetime(int(y), month, int(d), int(h), int(mi), int(s))
    except ValueError:
        return None
    if tz is not None:
        delta = LOCAL_OFF_MIN - tz_minutes(tz)
        if delta:
            ts += timedelta(minutes=delta)
    return ts


def parse_syslog_ts(line, now):
    m = SYSLOG_ISO_RE.match(line)
    if m:
        return make_ts(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), m.group(7))
    m = SYSLOG_CLASSIC_RE.match(line)
    if m:
        ts = make_ts(now.year, m.group(1), m.group(2), m.group(3), m.group(4), m.group(5))
        if ts and ts > now + timedelta(days=1):
            ts = ts.replace(year=now.year - 1)
        return ts
    return None


def fpm_line_ts(line):
    m = FPM_LOG_TS_RE.match(line)
    return make_ts(m.group(3), m.group(2), m.group(1), m.group(4), m.group(5), m.group(6)) if m else None


def files_for_window(patterns, start):
    """Rotated log files that may hold lines newer than `start` (by mtime), oldest first."""
    if isinstance(patterns, str):
        patterns = [patterns]
    cutoff = time.mktime(start.timetuple()) if start else None
    keep = []
    for pat in patterns:
        for f in (glob.glob(pat) if isinstance(pat, str) and any(c in pat for c in "*?[") else [pat]):
            try:
                st = os.stat(f)
            except OSError:
                continue
            if not os.path.isfile(f) or (cutoff and st.st_mtime < cutoff):
                continue
            keep.append((st.st_mtime, f))
    keep.sort()
    seen, out = set(), []
    for _, f in keep:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def iter_lines(path):
    """Stream lines of a plain or gzip log file."""
    try:
        if str(path).endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line.rstrip("\n")
            return
        with open(path, "rb") as fb:
            for raw in fb:
                yield raw.decode("utf-8", "replace").rstrip("\n")
    except (OSError, EOFError):
        return


def in_window(ts, start, end):
    return ts is not None and start <= ts <= end


def pct(part, whole):
    return (part * 100.0 / whole) if whole else 0.0


def fmt_kb(kb):
    if kb is None:
        return "n/a"
    mb = kb / 1024.0
    if mb >= 1024:
        return "%.2f GB" % (mb / 1024)
    return "%.1f MB" % mb if mb < 10 else "%.0f MB" % mb


def fmt_num(n):
    if n is None:
        return "n/a"
    if isinstance(n, float):
        return "{:,.1f}".format(n)
    return "{:,}".format(n)


def trunc(s, n):
    s = str(s)
    return s if len(s) <= n else s[:max(n - 1, 0)] + "…"


def to_mb(val):
    """'256M', '2G', '1048576' (bytes) -> MB. Returns None when unknown or unlimited."""
    if val is None:
        return None
    v = str(val).strip().strip('"').upper()
    m = re.match(r"^(-?\d+(?:\.\d+)?)\s*([KMGT]?)B?$", v)
    if not m:
        return None
    num = float(m.group(1))
    if num < 0:
        return None
    return num * {"": 1.0 / 1048576, "K": 1.0 / 1024, "M": 1.0, "G": 1024.0, "T": 1048576.0}[m.group(2)]


def sql_fingerprint(q, max_len=150):
    """Mask every literal so no customer data reaches the report."""
    q = " ".join(q.split())
    q = SQL_STRING_RE.sub("?", q)
    q = SQL_NUMBER_RE.sub("?", q)
    q = SQL_INLIST_RE.sub("(?+)", q)
    return trunc(q, max_len)


def component_of(path):
    for rx, fmt in ((r"wp-content/plugins/([^/]+)/", "plugin:%s"), (r"wp-content/themes/([^/]+)/", "theme:%s"),
                    (r"wp-content/mu-plugins/([^/]+)", "mu-plugin:%s"), (r"/app/code/([^/]+/[^/]+)/", "magento-module:%s"),
                    (r"/vendor/([^/]+/[^/]+)/", "vendor:%s")):
        m = re.search(rx, path)
        if m:
            return fmt % m.group(1)
    if "/wp-includes/" in path or "/wp-admin/" in path:
        return "wordpress-core"
    return "app"


def uid_name(uid, cache={}):  # noqa: B006 - intentional cache
    if uid not in cache:
        try:
            cache[uid] = pwd.getpwuid(uid).pw_name
        except (KeyError, OverflowError, ValueError):
            cache[uid] = str(uid)
    return cache[uid]


def day_list(start, end):
    days, d = [], start.date()
    while d <= end.date():
        days.append(d)
        d += timedelta(days=1)
    return days


def nominal_ram_gb(total_kb):
    gb = total_kb / 1048576.0
    return min(RAM_TIERS_GB, key=lambda t: abs(t - gb)) if gb else 0


# ----------------------------------------------------------------------------
# Investigation window (interactive prompt)
# ----------------------------------------------------------------------------
REL_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*(m|min|mins|minutes|h|hr|hrs|hour|hours|d|day|days|w|week|weeks)(?:\s+ago)?$")
DT_FORMATS = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H",
              "%d-%m-%Y:%H:%M", "%d-%m-%Y:%H", "%d-%m-%Y %H:%M", "%d/%m/%Y %H:%M", "%Y/%m/%d %H:%M",
              "%b %d %Y %H:%M", "%d %b %Y %H:%M", "%b %d %H:%M", "%d %b %H:%M"]
DATE_FORMATS = ["%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%Y/%m/%d", "%b %d %Y", "%d %b %Y", "%B %d %Y", "%d %B %Y",
                "%b %d", "%d %b", "%B %d", "%d %B"]


def parse_when(text, now, is_end=False):
    """Parse a user-supplied date/time. Returns a naive datetime or raises ValueError."""
    t = " ".join(text.replace(",", " ").split())
    low = t.lower()
    if low in ("now", ""):
        return now
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if low == "today":
        return now if is_end else midnight
    if low == "yesterday":
        return midnight - timedelta(seconds=1) if is_end else midnight - timedelta(days=1)
    m = REL_RE.match(low)
    if m:
        n, unit = float(m.group(1)), m.group(2)[0]
        return now - timedelta(seconds=n * {"m": 60, "h": 3600, "d": 86400, "w": 604800}[unit])
    for fmt in DT_FORMATS + DATE_FORMATS:
        try:
            # A fixed leap year lets "Feb 29" parse for the year-less formats.
            dt = datetime.strptime(t + " 2000", fmt + " %Y") if "%Y" not in fmt else datetime.strptime(t, fmt)
        except ValueError:
            continue
        if "%Y" not in fmt:
            try:
                dt = dt.replace(year=now.year)
                if dt > now + timedelta(days=1):
                    dt = dt.replace(year=now.year - 1)
            except ValueError:
                continue
        if fmt in DATE_FORMATS and is_end:
            dt = dt.replace(hour=23, minute=59, second=59)
        return dt
    raise ValueError("could not understand '%s'" % text)


def open_tty():
    """Return (reader, writer) for interactive prompts even when the script arrives on stdin (curl | python3 -)."""
    if sys.stdin is not None and sys.stdin.isatty():
        return sys.stdin, sys.stderr
    try:
        return open("/dev/tty", "r"), open("/dev/tty", "w")
    except OSError:
        return None, None


def resolve_window(args, now):
    """Decide the investigation window from flags, or ask for it. Returns (start, end, how)."""
    if args.last:
        return parse_when(args.last, now), now, "--last " + args.last
    if args.from_time or args.to_time:
        start = parse_when(args.from_time, now) if args.from_time else now - timedelta(days=7)
        end = parse_when(args.to_time, now, is_end=True) if args.to_time else now
        return start, min(end, now), "command line"
    rd, wr = open_tty()
    if rd is None:
        return now - timedelta(days=7), now, "default (no terminal to ask - last 7 days)"

    def ask(label, default_desc, is_end):
        for _ in range(5):
            wr.write("  %s [Enter = %s]: " % (label, default_desc))
            wr.flush()
            ans = rd.readline()
            if not ans or not ans.strip():
                return None
            try:
                return parse_when(ans.strip(), now, is_end=is_end)
            except ValueError as exc:
                wr.write("    %s - try again.\n" % exc)
        raise SystemExit("Too many invalid attempts.")

    wr.write("\nCloudways Server RCA Investigator v%s\n" % VERSION)
    wr.write("Server time now: %s %s\n" % (now.strftime("%Y-%m-%d %H:%M"), TZ_NAME))
    wr.write("Enter the investigation window in server time. Accepted examples:\n")
    wr.write("  2026-11-05 | 2026-11-05 14:30 | 05-11-2026 | Nov 5 | yesterday | 7d | 24h | now\n\n")
    wr.flush()
    for _ in range(5):
        start = ask("From date/time", "7 days ago", False) or now - timedelta(days=7)
        end = min(ask("To date/time  ", "now", True) or now, now)
        if start < end:
            wr.write("\n")
            wr.flush()
            return start, end, "interactive"
        wr.write("    'From' must be earlier than 'To' (and not in the future) - try again.\n")
    raise SystemExit("Could not get a valid window.")


# ----------------------------------------------------------------------------
# Discovery: applications, PHP-FPM pools, process classification
# ----------------------------------------------------------------------------
def parse_server_name(conf):
    txt = read_text(conf, 200000) or ""
    pref, fall = [], []
    for raw in txt.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line.startswith("server_name"):
            continue
        for host in line.rstrip(";").split()[1:]:
            host = host.strip().lower().lstrip("*.")
            if not host or host == "_":
                continue
            fall.append(host)
            if "cloudwaysapps.com" not in host:
                pref.append(host)
    return (pref or fall or [""])[0]


def detect_app_type(app_dir):
    ph = os.path.join(app_dir, "public_html")
    if os.path.exists(os.path.join(ph, "wp-config.php")):
        return "woocommerce" if os.path.isdir(os.path.join(ph, "wp-content", "plugins", "woocommerce")) else "wordpress"
    if os.path.exists(os.path.join(ph, "app", "etc", "env.php")):
        return "magento"
    if os.path.exists(os.path.join(ph, "artisan")):
        return "laravel"
    return "php"


def collect_apps(ctx):
    roots = [ctx.args.apps_root] + sorted(glob.glob("/home/*/applications")) + sorted(glob.glob("/home/*.cloudwaysapps.com"))
    apps, seen_real = {}, set()
    for root in roots:
        try:
            children = sorted(os.listdir(root))
        except OSError:
            continue
        for name in children:
            d = os.path.join(root, name)
            logs = os.path.join(d, "logs")
            if name.startswith(".") or name in apps or not os.path.isdir(d):
                continue
            if not (os.path.isdir(logs) or os.path.isdir(os.path.join(d, "public_html"))):
                continue
            real = os.path.realpath(d)
            if real in seen_real:
                continue
            seen_real.add(real)
            try:
                names = os.listdir(logs)
            except OSError:
                names = []
            nginx = [os.path.join(logs, n) for n in names if n.startswith("nginx-app.status.log")] or \
                    [os.path.join(logs, n) for n in names if n.startswith("nginx") and ".access.log" in n]
            backend = [os.path.join(logs, n) for n in names
                       if (n.startswith("backend") or n.startswith("apache")) and ".access.log" in n]
            apps[name] = {
                "app": name, "dir": d, "domain": parse_server_name(os.path.join(d, "conf", "server.nginx")),
                "type": detect_app_type(d), "web_logs": nginx or backend,
                "web_log_kind": "nginx" if nginx else ("backend" if backend else ""),
                "fpm_access_logs": [os.path.join(logs, n) for n in names if n.startswith("php-app.access.log")],
                "fpm_slow_logs": [os.path.join(logs, n) for n in names if n.startswith("php-app.slow.log")],
            }
    return apps


POOL_KEYS = ("user", "pm", "pm.max_children", "pm.max_requests", "request_terminate_timeout",
             "php_admin_value[memory_limit]", "php_value[memory_limit]")


def _parse_pool_file(path, cur, pools, ver, depth=0):
    txt = read_text(path, 500000)
    if txt is None or depth > 4:
        return cur
    for raw in txt.splitlines():
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        m = re.match(r"^\[([^\]]+)\]$", line)
        if m:
            name = m.group(1).strip()
            cur = None if name.lower() == "global" else pools.setdefault(name, {"pool": name, "php": ver})
            continue
        if "=" not in line:
            continue
        key, val = [x.strip() for x in line.split("=", 1)]
        val = val.split(";", 1)[0].strip().strip('"').strip("'")
        if key == "include":
            for inc in sorted(glob.glob(val)) or [val]:
                cur = _parse_pool_file(inc, cur, pools, ver, depth + 1)
        elif cur is not None and key in POOL_KEYS:
            cur[key] = val
    return cur


def collect_pools(ctx):
    pools = {}
    for conf in sorted(glob.glob("/etc/php/*/fpm/pool.d/*.conf")) + sorted(glob.glob("/etc/php-fpm.d/*.conf")):
        if conf.endswith("placeholder.conf"):
            continue
        m = re.search(r"/php/([\d.]+)/", conf)
        _parse_pool_file(conf, None, pools, m.group(1) if m else "")
    users = defaultdict(set)
    for name, p in pools.items():
        base = POOL_SUFFIX_RE.sub("", name)
        p["app"] = base if base in ctx.apps else (name if name in ctx.apps else base)
        if p.get("user") and p["app"] in ctx.apps:
            users[p["user"]].add(p["app"])
    ctx.user_to_app = {u: next(iter(a)) for u, a in users.items() if len(a) == 1}
    for app in ctx.apps:
        ctx.user_to_app.setdefault(app, app)
    return pools


def classify(ctx, comm, cmd="", uid=None):
    """Map a process to (kind, owner): ('app', <app>), ('service', <label>) or ('other', <name>)."""
    key = (comm, cmd if "pool " in cmd else "", uid)
    hit = ctx._class_cache.get(key)
    if hit:
        return hit
    c = comm.strip()
    res = None
    if c.startswith("php-fpm") or cmd.startswith("php-fpm"):
        m = re.search(r"pool (\S+)", cmd)
        if m:
            pool = m.group(1)
            res = ("app", ctx.pools.get(pool, {}).get("app") or POOL_SUFFIX_RE.sub("", pool))
        elif uid is not None and uid_name(uid) in ctx.user_to_app:
            res = ("app", ctx.user_to_app[uid_name(uid)])
        else:
            res = ("service", "php-fpm")
    if res is None:
        for label, rx in SERVICE_PATTERNS:
            if rx.search(c):
                res = ("service", label)
                break
    if res is None and uid is not None and uid_name(uid) in ctx.user_to_app:
        res = ("app", ctx.user_to_app[uid_name(uid)])
    if res is None:
        first = (c.split() or ["?"])[0].rstrip(":")
        if KERNEL_THREAD_RE.match(first):
            res = ("other", "kernel threads")
        else:
            res = ("other", os.path.basename(first) or first)
    if len(ctx._class_cache) > 200000:
        ctx._class_cache.clear()
    ctx._class_cache[key] = res
    return res


def owner_label(ctx, kind, owner, internal=True):
    if kind == "app":
        dom = ctx.apps.get(owner, {}).get("domain")
        return "app:%s%s" % (owner, " (%s)" % dom if dom else "")
    if kind == "service":
        return owner if internal or owner != "imunify" else "system"
    return owner


def role_of(kind, owner):
    return ROLE.get(owner if kind == "service" else kind, ROLE["other"])


# ----------------------------------------------------------------------------
# Baseline and current state
# ----------------------------------------------------------------------------
def read_meminfo():
    out = {}
    for line in (read_text("/proc/meminfo") or "").splitlines():
        p = line.split()
        if len(p) >= 2 and p[1].isdigit():
            out[p[0].rstrip(":")] = int(p[1])
    return out


def read_procs(ctx):
    procs = []
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return procs
    for pid in pids:
        try:
            with open("/proc/%s/stat" % pid, "r", errors="replace") as f:
                s = f.read()
            lp, rp = s.index("("), s.rindex(")")
            rest = s[rp + 2:].split()
            uid = os.stat("/proc/" + pid).st_uid
            cmd = (read_text("/proc/%s/cmdline" % pid, 4000) or "").replace("\0", " ").strip()
            procs.append({"pid": int(pid), "comm": s[lp + 1:rp], "uid": uid, "rss_kb": int(rest[21]) * PAGE_KB,
                          "cpu_ticks": int(rest[11]) + int(rest[12]), "cmd": cmd})
        except (OSError, ValueError, IndexError):
            continue
    for p in procs:
        p["kind"], p["owner"] = classify(ctx, p["comm"], p["cmd"], p["uid"])
    return procs


def server_baseline(ctx):
    b = {"hostname": socket.gethostname(), "ncpu": NCPU}
    rc, out, _ = run_cmd(["hostname", "-I"], 5)
    b["ips"] = out.split() if rc == 0 else []
    try:
        u = os.uname()
        b["kernel"] = u.release
    except AttributeError:
        b["kernel"] = "?"
    m = re.search(r'^PRETTY_NAME="?([^"\n]+)', read_text("/etc/os-release") or "", re.M)
    b["os"] = m.group(1) if m else "?"
    mem = read_meminfo()
    b["mem"] = mem
    tot = mem.get("MemTotal", 0)
    avail = mem.get("MemAvailable", mem.get("MemFree", 0) + mem.get("Cached", 0))
    b["ram_kb"], b["ram_used_kb"], b["ram_used_pct"] = tot, tot - avail, pct(tot - avail, tot)
    b["ram_gb"] = nominal_ram_gb(tot)
    b["swap_kb"] = mem.get("SwapTotal", 0)
    b["swap_used_kb"] = mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)
    b["load"] = (read_text("/proc/loadavg") or "").split()[:3]
    m = re.search(r"^btime (\d+)", read_text("/proc/stat") or "", re.M)
    b["boot"] = datetime.fromtimestamp(int(m.group(1))) if m else None
    b["swappiness"] = (read_text("/proc/sys/vm/swappiness") or "").strip()
    fs, seen = [], set()
    for mnt in ("/", "/home", "/var", "/var/lib/mysql", "/mnt", "/tmp"):
        try:
            st = os.statvfs(mnt)
        except OSError:
            continue
        key = (st.f_blocks, st.f_files)
        if not st.f_blocks or key in seen:
            continue
        seen.add(key)
        total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
        fs.append({"mount": mnt, "size_gb": total / 1e9, "used_pct": pct(total - free, total),
                   "inode_pct": pct(st.f_files - st.f_favail, st.f_files) if st.f_files else 0.0})
    b["filesystems"] = fs
    types = Counter(a["type"] for a in ctx.apps.values())
    b["apps"] = len(ctx.apps)
    b["app_types"] = types.most_common()
    return b


def live_state(ctx):
    procs = read_procs(ctx)
    groups = defaultdict(lambda: {"n": 0, "rss_kb": 0})
    for p in procs:
        g = groups[(p["kind"], p["owner"])]
        g["n"] += 1
        g["rss_kb"] += p["rss_kb"]
    workers = [p["rss_kb"] for p in procs if p["kind"] == "app" and p["comm"].startswith("php-fpm")]
    return {"procs": sorted(procs, key=lambda p: -p["rss_kb"])[:12],
            "groups": sorted(groups.items(), key=lambda kv: -kv[1]["rss_kb"]),
            "fpm_worker_avg_kb": (sum(workers) / len(workers)) if workers else None, "fpm_workers": len(workers),
            "all": procs}


def service_status(ctx):
    rc, out, _ = run_cmd(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"], 15)
    if rc != 0:
        ctx.note("systemctl not available - current service status was not collected.")
        return []
    res = []
    for line in out.splitlines():
        parts = line.split()
        unit = parts[0] if parts else ""
        if not unit.endswith(".service") or not WATCH_UNIT_RE.match(unit) or "@" in unit:
            continue
        rc2, o2, _ = run_cmd(["systemctl", "show", unit, "--no-pager",
                              "-p", "LoadState,ActiveState,SubState,ActiveEnterTimestamp,NRestarts,MemoryCurrent"], 10)
        kv = dict(l.split("=", 1) for l in o2.splitlines() if "=" in l)
        if kv.get("LoadState") in ("not-found", "masked"):
            continue
        m = re.search(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", kv.get("ActiveEnterTimestamp", ""))
        since = make_ts(*m.groups()) if m else None
        mem = kv.get("MemoryCurrent", "")
        res.append({"unit": unit[:-8], "active": kv.get("ActiveState", "?"), "sub": kv.get("SubState", "?"),
                    "since": since, "nrestarts": int(kv["NRestarts"]) if kv.get("NRestarts", "").isdigit() else None,
                    "mem_kb": int(mem) // 1024 if mem.isdigit() and int(mem) < 1 << 60 else None})
    return res


# ----------------------------------------------------------------------------
# System logs: OOM kills and service events (syslog / kern.log / journal)
# ----------------------------------------------------------------------------
class SysLogScanner:
    """Single-pass parser for kernel OOM reports and systemd service events."""

    def __init__(self, ctx, start, end, now=None):
        self.ctx, self.start, self.end = ctx, start, end
        self.now = now or datetime.now()
        self.oom = []
        self.svc_events = []
        self.svc_starts = Counter()       # (service, 'YYYY-MM-DD') -> count
        self._seen_oom = defaultdict(list)
        self._seen_evt = set()
        self.reset_state()

    def reset_state(self):
        self.st = {"collect": False, "snap": None, "trigger": None, "swap_free": None, "swap_total": None,
                   "memcg": False}

    def feed(self, line):
        st = self.st
        if st["collect"]:
            if "Killed process" not in line and "oom-kill:" not in line:
                m = OOM_TASK_RE.search(line)
                if m:
                    rest = m.group(6).split()
                    i = 0
                    while i < len(rest) and rest[i].lstrip("-").isdigit():
                        i += 1
                    name = " ".join(rest[i:])
                    if name:
                        st["snap"][(int(m.group(2)), name)] += int(m.group(5)) * PAGE_KB
                return
        if "systemd[1]:" in line:
            self._systemd(line)
            return
        if "oom" not in line and "Killed process" not in line and "swap" not in line:
            return
        if "invoked oom-killer" in line:
            m = OOM_INVOKED_RE.search(line)
            self.reset_state()
            self.st["trigger"] = m.group(1).split(":")[-1] if m else None
        elif "oom_score_adj" in line and "name" in line:
            st["collect"], st["snap"] = True, defaultdict(int)
        elif "Free swap" in line:
            m = re.search(r"Free swap\s*=\s*(\d+)kB", line)
            if m:
                st["swap_free"] = int(m.group(1))
        elif "Total swap" in line:
            m = re.search(r"Total swap\s*=\s*(\d+)kB", line)
            if m:
                st["swap_total"] = int(m.group(1))
        elif "oom-kill:" in line:
            st["collect"] = False
            st["memcg"] = "CONSTRAINT_MEMCG" in line
        elif "Killed process" in line:
            self._killed(line)

    def _killed(self, line):
        st = self.st
        m = OOM_KILLED_RE.search(line)
        ts = parse_syslog_ts(line, self.now)
        self.reset_state()
        if not m or not in_window(ts, self.start, self.end):
            return
        pid, name = int(m.group(1)), m.group(2)
        if any(abs((ts - t).total_seconds()) < 120 for t in self._seen_oom[(pid, name)]):
            return
        self._seen_oom[(pid, name)].append(ts)
        rss = re.search(r"anon-rss:(\d+)kB", line)
        uid = re.search(r"UID:(\d+)", line)
        ev = {"ts": ts, "pid": pid, "name": name, "uid": int(uid.group(1)) if uid else None,
              "anon_rss_kb": int(rss.group(1)) if rss else None,
              "cgroup": st["memcg"] or "Memory cgroup out of memory" in line,
              "trigger": st["trigger"], "swap_free_kb": st["swap_free"], "swap_total_kb": st["swap_total"],
              "holders": [], "snap_total_kb": 0, "raw": trunc(line, 260)}
        ev["kind"], ev["owner"] = classify(self.ctx, name, "", ev["uid"])
        if st["snap"]:
            agg = defaultdict(int)
            for (tuid, tname), kb in st["snap"].items():
                agg[classify(self.ctx, tname, "", tuid)] += kb
            ev["snap_total_kb"] = sum(agg.values())
            ev["holders"] = sorted(((k[0], k[1], v) for k, v in agg.items()), key=lambda x: -x[2])[:12]
        self.oom.append(ev)

    def _systemd(self, line):
        what = unit = None
        m = SD_EXIT_RE.search(line)
        if m:
            unit, what = m.group(1), "main process exited (%s, status=%s)" % (m.group(2), m.group(3))
            if m.group(2) == "exited" and m.group(3).startswith("0"):
                return
        if not m:
            m = SD_FAIL_RE.search(line)
            if m:
                unit, what = m.group(1), "failed (result '%s')" % m.group(2)
        if not m:
            m = SD_RESTART_RE.search(line)
            if m:
                unit, what = m.group(1), "auto-restart scheduled (counter %s)" % m.group(2)
        if not m:
            m = SD_OOM_RE.search(line)
            if m:
                unit, what = m.group(1), "a process of this unit was killed by the OOM killer"
        if m:
            if not WATCH_UNIT_RE.match(unit):
                return
            ts = parse_syslog_ts(line, self.now)
            key = (ts, unit, what)
            if in_window(ts, self.start, self.end) and key not in self._seen_evt:
                self._seen_evt.add(key)
                self.svc_events.append({"ts": ts, "unit": unit, "what": what})
            return
        m = SD_STARTED_RE.search(line)
        if m:
            desc = m.group(1)
            for svc, rx in SVC_KEYWORDS:
                if rx.search(desc):
                    ts = parse_syslog_ts(line, self.now)
                    key = (ts, svc, "started")
                    if in_window(ts, self.start, self.end) and key not in self._seen_evt:
                        self._seen_evt.add(key)
                        self.svc_starts[(svc, ts.strftime("%Y-%m-%d"))] += 1
                    break


def first_ts_of(path, now):
    for i, line in enumerate(iter_lines(path)):
        ts = parse_syslog_ts(line, now)
        if ts or i > 20:
            return ts
    return None


def scan_system_logs(ctx, start, end):
    now = datetime.now()
    sc = SysLogScanner(ctx, start, end, now)
    sources, coverage = [], []
    for pattern in SYSLOG_PATTERNS:
        every = [f for f in glob.glob(pattern) if os.path.isfile(f)]
        files = [f for f in files_for_window(pattern, start) if os.access(f, os.R_OK)]
        if every and not files and not any(os.access(f, os.R_OK) for f in every):
            ctx.note("%s is not readable - run as root for complete OOM / service history." % pattern)
            continue
        if not files:
            continue
        oldest = min(every, key=lambda f: os.stat(f).st_mtime)
        if os.access(oldest, os.R_OK):
            ts = first_ts_of(oldest, now)
            if ts:
                coverage.append(ts)
        for f in files:
            sc.reset_state()
            for line in iter_lines(f):
                sc.feed(line)
        sources.append("%s (%d file(s))" % (pattern, len(files)))
    since, until = start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S")
    for label, extra in ((("journalctl -k", ["-k"]), ("journalctl _PID=1", ["_PID=1"])) if USE_JOURNAL else ()):
        n = 0
        sc.reset_state()
        for line in stream_cmd(["journalctl", "--no-pager", "-o", "short-iso", "--since", since, "--until", until] + extra,
                               timeout=120):
            n += 1
            sc.feed(line)
        if n > 1:
            sources.append("%s (%s lines)" % (label, fmt_num(n)))
    if not sources:
        ctx.note("No kernel/system log source was readable (syslog, kern.log, journal) - OOM kills and service "
                 "crashes could NOT be checked. Run as root.")
    cov = min(coverage) if coverage else None
    if cov and cov > start + timedelta(hours=1) and not any(s.startswith("journalctl") for s in sources):
        ctx.note("System log files only go back to %s - the earlier part of the window is not covered for "
                 "OOM / service events." % cov.strftime("%Y-%m-%d %H:%M"))
    sc.oom.sort(key=lambda e: e["ts"])
    sc.svc_events.sort(key=lambda e: e["ts"])
    return {"oom": sc.oom, "svc_events": sc.svc_events, "svc_starts": sc.svc_starts, "sources": sources,
            "checked": bool(sources), "coverage_from": cov}


# ----------------------------------------------------------------------------
# Reboots
# ----------------------------------------------------------------------------
LAST_DATE_RE = re.compile(r"[A-Z][a-z]{2} ([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})")


def scan_reboots(ctx, start, end, boot_now):
    boots, shutdowns, have_last = [], [], False
    for wtmp in ["/var/log/wtmp"] + sorted(glob.glob("/var/log/wtmp.*")):
        if not os.path.isfile(wtmp) or wtmp.endswith(".gz"):
            continue
        rc, out, _ = run_cmd(["last", "-x", "-F", "-f", wtmp, "reboot", "shutdown"], 20)
        if rc != 0:
            continue
        have_last = True
        for line in out.splitlines():
            m = LAST_DATE_RE.search(line)
            if not m:
                continue
            ts = make_ts(m.group(6), m.group(1), m.group(2), m.group(3), m.group(4), m.group(5))
            if ts and line.startswith("reboot"):
                boots.append(ts)
            elif ts and line.startswith("shutdown"):
                shutdowns.append(ts)
    rc = 1
    if ctx.is_root and USE_JOURNAL:
        rc, out, _ = run_cmd(["journalctl", "--list-boots", "--no-pager"], 20)
        rows = [l for l in out.splitlines() if re.match(r"^\s*-?\d+\s+[0-9a-f]{32}\s", l)] if rc == 0 else []
        for line in rows[1:]:
            m = re.search(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", line)
            if m:
                boots.append(make_ts(*m.groups()))
    if boot_now:
        boots.append(boot_now)
    uniq = []
    for ts in sorted(b for b in boots if b):
        if not uniq or (ts - uniq[-1]).total_seconds() > 300:
            uniq.append(ts)
    res = []
    for ts in uniq:
        if not in_window(ts, start, end):
            continue
        clean = None
        if have_last:
            clean = any(0 <= (ts - s).total_seconds() <= 900 for s in shutdowns)
        res.append({"ts": ts, "clean": clean})
    if not have_last and rc != 0 and not boot_now:
        ctx.note("Neither wtmp (last) nor the journal was readable - reboot history unavailable.")
    return res


# ----------------------------------------------------------------------------
# Resource history (atop)
# ----------------------------------------------------------------------------
def atop_history(ctx, start, end):
    if not shutil.which("atop"):
        ctx.note("atop is not installed - no historical CPU/memory per day or per consumer.")
        return None
    owners = defaultdict(lambda: {"cpu_sum": 0.0, "cpu_peak": 0.0, "cpu_peak_at": "", "rss_sum": 0.0,
                                  "rss_peak": 0.0, "rss_peak_at": "", "n": 0})
    days = {}
    worst_cpu, worst_mem = [], []
    tot = {"n": 0, "files": 0, "interval": 0, "mem_total_kb": 0}

    def flush(s):
        if "ep" not in s or "cpu_busy" not in s:
            return
        ts = datetime.fromtimestamp(s["ep"])
        iv = s["iv"]
        if not in_window(ts, start, end) or iv <= 0 or iv > 3600:
            return
        oc, orss = defaultdict(float), defaultdict(float)
        for pid, name, ticks, used in s["prc"]:
            cmd, ruid = s["prg"].get(pid, ("", None))
            oc[classify(ctx, name, cmd, ruid)] += used * 100.0 / max(ticks * iv, 1)
        for pid, name, rss in s["prm"]:
            cmd, ruid = s["prg"].get(pid, ("", None))
            orss[classify(ctx, name, cmd, ruid)] += rss
        stamp = ts.strftime("%Y-%m-%d %H:%M")
        for key in set(oc) | set(orss):
            o = owners[key]
            c, r = oc.get(key, 0.0), orss.get(key, 0.0)
            o["cpu_sum"] += c
            o["rss_sum"] += r
            o["n"] += 1
            if c > o["cpu_peak"]:
                o["cpu_peak"], o["cpu_peak_at"] = c, stamp
            if r > o["rss_peak"]:
                o["rss_peak"], o["rss_peak_at"] = r, stamp
        d = days.setdefault(ts.strftime("%Y-%m-%d"), {"n": 0, "cpu_sum": 0.0, "cpu_peak": 0.0, "cpu_high": 0,
                                                    "mem_sum": 0.0, "mem_peak": 0.0, "mem_high": 0, "swap_peak_kb": 0.0,
                                                    "load_peak": 0.0, "iowait_sum": 0.0, "steal_sum": 0.0})
        cpu, mem = s["cpu_busy"], s.get("mem_used_pct", 0.0)
        d["n"] += 1
        d["cpu_sum"] += cpu
        d["cpu_peak"] = max(d["cpu_peak"], cpu)
        d["cpu_high"] += 1 if cpu >= 85 else 0
        d["mem_sum"] += mem
        d["mem_peak"] = max(d["mem_peak"], mem)
        d["mem_high"] += 1 if mem >= 90 else 0
        d["swap_peak_kb"] = max(d["swap_peak_kb"], s.get("swap_used_kb", 0.0))
        d["load_peak"] = max(d["load_peak"], s.get("load1", 0.0))
        d["iowait_sum"] += s.get("iowait", 0.0)
        d["steal_sum"] += s.get("steal", 0.0)
        tot["n"] += 1
        tot["interval"] = iv
        tot["mem_total_kb"] = s.get("mem_total_kb", tot["mem_total_kb"])
        top_c = sorted(oc.items(), key=lambda kv: -kv[1])[:3]
        top_m = sorted(orss.items(), key=lambda kv: -kv[1])[:3]
        worst_cpu.append((cpu, stamp, [(k, v) for k, v in top_c]))
        worst_mem.append((mem, stamp, [(k, v) for k, v in top_m], s.get("swap_used_kb", 0.0)))
        if len(worst_cpu) > 400:
            worst_cpu.sort(key=lambda x: -x[0])
            del worst_cpu[8:]
            worst_mem.sort(key=lambda x: -x[0])
            del worst_mem[8:]

    def new_sample():
        return {"prc": [], "prm": [], "prg": {}}

    for day in day_list(start, end):
        cands = sorted(glob.glob(os.path.join(ATOP_DIR, "atop_%s*" % day.strftime("%Y%m%d"))), key=len)
        if not cands:
            continue
        f = cands[0]
        if not os.access(f, os.R_OK):
            ctx.note("atop raw logs are not readable - run as root for CPU/memory history.")
            break
        b = start.strftime("%H:%M") if day == start.date() else "00:00"
        e = end.strftime("%H:%M") if day == end.date() else "23:59"
        tot["files"] += 1
        s = new_sample()
        for line in stream_cmd(["atop", "-r", f, "-b", b, "-e", e, "-P", "CPU,CPL,MEM,SWP,PRG,PRC,PRM"],
                               timeout=ctx.args.atop_timeout):
            if line == "SEP":
                flush(s)
                s = new_sample()
                continue
            head = line[:4]
            if head in ("CPU ", "CPL ", "MEM ", "SWP "):
                p = line.split()
                if len(p) < 8 or not p[2].isdigit():
                    continue
                s["ep"], s["iv"] = int(p[2]), int(p[5]) if p[5].isdigit() else 0
                if head == "CPL ":
                    try:
                        s["load1"] = float(p[7])
                    except ValueError:
                        pass
                    continue
                r = [int(x) for x in p[6:] if x.lstrip("-").isdigit()]
                if head == "CPU " and len(r) >= 10:
                    sys_, usr, nice, idle, wait, irq, sirq, steal = r[2:10]
                    total = sys_ + usr + nice + idle + wait + irq + sirq + steal or 1
                    s["cpu_busy"] = pct(total - idle - wait, total)
                    s["iowait"], s["steal"] = pct(wait, total), pct(steal, total)
                elif head == "MEM " and len(r) >= 8:
                    pg, phys, free, cache, buf, _slab, _dirty, slabrec = r[:8]
                    shmem = r[9] if len(r) > 9 else 0
                    avail = free + cache + buf + slabrec - shmem
                    s["mem_used_pct"] = max(0.0, pct(phys - avail, phys))
                    s["mem_total_kb"] = phys * pg / 1024.0
                elif head == "SWP " and len(r) >= 3:
                    s["swap_used_kb"] = (r[1] - r[2]) * r[0] / 1024.0
                continue
            if head not in ("PRC ", "PRM ", "PRG "):
                continue
            m = ATOP_PROC_RE.match(line)
            if not m:
                continue
            label, pid, name, state, rest = m.group(1), int(m.group(7)), m.group(8), m.group(9), m.group(10)
            fld = rest.split()
            try:
                if label == "PRG":
                    cm = re.search(r"\((.*?)\s*\)", rest)
                    s["prg"][pid] = (cm.group(1).strip() if cm else "", int(fld[0]) if fld[0].isdigit() else None)
                elif label == "PRC" and not (len(fld) > 10 and fld[10] == "n"):
                    s["prc"].append((pid, name, int(fld[0]), int(fld[1]) + int(fld[2])))
                elif label == "PRM" and state != "E" and not (len(fld) > 13 and fld[13] == "n"):
                    s["prm"].append((pid, name, int(fld[2])))
            except (ValueError, IndexError):
                continue
        flush(s)
    if not tot["n"]:
        if tot["files"]:
            ctx.note("atop raw logs exist but returned no samples for the window.")
        else:
            ctx.note("No atop raw log (/var/log/atop/atop_YYYYMMDD) covers the window - CPU/memory history unavailable.")
        return None
    n = tot["n"]
    for d in days.values():
        d["cpu_avg"], d["mem_avg"] = d["cpu_sum"] / d["n"], d["mem_sum"] / d["n"]
        d["iowait"], d["steal"] = d["iowait_sum"] / d["n"], d["steal_sum"] / d["n"]
    out_owners = []
    for (kind, owner), o in owners.items():
        out_owners.append({"kind": kind, "owner": owner, "cpu_avg": o["cpu_sum"] / n, "cpu_peak": o["cpu_peak"],
                           "cpu_peak_at": o["cpu_peak_at"], "rss_avg_kb": o["rss_sum"] / max(o["n"], 1),
                           "rss_peak_kb": o["rss_peak"], "rss_peak_at": o["rss_peak_at"], "seen": o["n"]})
    worst_cpu.sort(key=lambda x: -x[0])
    worst_mem.sort(key=lambda x: -x[0])
    return {"days": days, "owners": out_owners, "intervals": n, "interval_s": tot["interval"], "files": tot["files"],
            "mem_total_kb": tot["mem_total_kb"],
            "cpu_avg": sum(d["cpu_sum"] for d in days.values()) / n,
            "cpu_peak": max(d["cpu_peak"] for d in days.values()),
            "cpu_high": sum(d["cpu_high"] for d in days.values()),
            "mem_avg": sum(d["mem_sum"] for d in days.values()) / n,
            "mem_peak": max(d["mem_peak"] for d in days.values()),
            "mem_high": sum(d["mem_high"] for d in days.values()),
            "swap_peak_kb": max(d["swap_peak_kb"] for d in days.values()),
            "iowait": sum(d["iowait_sum"] for d in days.values()) / n,
            "steal": sum(d["steal_sum"] for d in days.values()) / n,
            "worst_cpu": worst_cpu[:6], "worst_mem": worst_mem[:6]}


# ----------------------------------------------------------------------------
# PHP-FPM: master logs, per-app access logs and slow logs
# ----------------------------------------------------------------------------
def pool_app(ctx, pool):
    return ctx.pools.get(pool, {}).get("app") or POOL_SUFFIX_RE.sub("", pool)


def scan_fpm_master_logs(ctx, start, end):
    per = defaultdict(lambda: {"max_children": 0, "limit": None, "sigkill": 0, "sigsegv": 0, "timeouts": 0,
                               "by_day": Counter()})
    by_hour, restarts = Counter(), Counter()
    every = glob.glob(FPM_LOG_GLOB)
    files = [f for f in files_for_window(FPM_LOG_GLOB, start) if os.access(f, os.R_OK)]
    if every and not any(os.access(f, os.R_OK) for f in every):
        ctx.note("PHP-FPM master logs (/var/log/php*-fpm.log) are not readable - max_children events unavailable (run as root).")
    for f in files:
        for line in iter_lines(f):
            if "max_children" in line or "exited on signal" in line or "timed out" in line:
                ts = fpm_line_ts(line)
                pm = FPM_POOL_RE.search(line)
                if not pm or not in_window(ts, start, end):
                    continue
                o = per[pool_app(ctx, pm.group(1))]
                mc = FPM_MAXCHILD_RE.search(line)
                if mc:
                    o["max_children"] += 1
                    o["limit"] = int(mc.group(1))
                    o["by_day"][ts.strftime("%Y-%m-%d")] += 1
                    by_hour[ts.strftime("%Y-%m-%d %H")] += 1
                elif "timed out" in line:
                    o["timeouts"] += 1
                else:
                    sg = FPM_SIGNAL_RE.search(line)
                    if sg and sg.group(1) == "9":
                        o["sigkill"] += 1
                    elif sg and sg.group(1) == "11":
                        o["sigsegv"] += 1
            elif "ready to handle connections" in line:
                ts = fpm_line_ts(line)
                if in_window(ts, start, end):
                    restarts[ts.strftime("%Y-%m-%d")] += 1
    return {"per_app": dict(per), "by_hour": by_hour, "restarts": restarts, "files": len(files)}


class HourCache:
    """Maps an access-log hour string to (flag, 'YYYY-MM-DD HH', base datetime) once per distinct hour."""

    def __init__(self, start, end):
        self.start, self.end, self.cache = start, end, {}

    def get(self, hs, tz):
        key = (hs, tz)
        hit = self.cache.get(key)
        if hit is None:
            try:
                d, mon, rest = hs.split("/")
                y, h = rest.split(":")
                base = make_ts(y, mon, d, h, 0, 0, tz)
            except ValueError:
                base = None
            if base is None:
                hit = (0, "", None)
            else:
                nxt = base + timedelta(hours=1)
                flag = 0 if (nxt <= self.start or base > self.end) else (
                    1 if (base >= self.start and nxt <= self.end) else 2)
                hit = (flag, base.strftime("%Y-%m-%d %H"), base)
            self.cache[key] = hit
        return hit


def is_bot_ua(ua, cache={}):  # noqa: B006 - intentional cache
    hit = cache.get(ua)
    if hit is None:
        low = ua.lower()
        hit = (not low or low == "-") or any(mk in low for mk in BOT_UA_MARKERS)
        if len(cache) < 50000:
            cache[ua] = hit
    return hit


def scan_traffic(ctx, start, end, deadline):
    """Per-application web access logs: requests, 5xx, top IPs, bots, login/xmlrpc abuse, per-hour totals."""
    hc = HourCache(start, end)
    per, hour_req, hour_5xx = {}, Counter(), Counter()
    skipped, unreadable = [], 0
    sized = []
    for name, app in ctx.apps.items():
        files = files_for_window(app["web_logs"], start)
        size = sum(os.path.getsize(f) for f in files if os.path.exists(f))
        sized.append((size, name, files))
    sized.sort(reverse=True)
    for size, name, files in sized:
        if not files:
            continue
        if time.time() > deadline:
            skipped.append(name)
            continue
        a = {"req": 0, "s5": 0, "s4": 0, "bots": 0, "login": 0, "xmlrpc": 0, "ips": Counter(), "hours": Counter(),
             "status": Counter(), "partial": False}
        n = 0
        for f in files:
            if not os.access(f, os.R_OK):
                unreadable += 1
                continue
            for line in iter_lines(f):
                m = ACCESS_RE.match(line)
                if not m:
                    continue
                flag, hk, base = hc.get(m.group(2), m.group(4))
                if flag == 0:
                    continue
                if flag == 2 and not in_window(base + timedelta(minutes=int(m.group(3))), start, end):
                    continue
                n += 1
                status = m.group(7)
                a["req"] += 1
                a["hours"][hk] += 1
                a["status"][status] += 1
                a["ips"][m.group(1)] += 1
                hour_req[hk] += 1
                if status[0] == "5":
                    a["s5"] += 1
                    hour_5xx[hk] += 1
                elif status[0] == "4":
                    a["s4"] += 1
                uri = m.group(6)
                if "wp-login.php" in uri:
                    a["login"] += 1
                elif "xmlrpc.php" in uri:
                    a["xmlrpc"] += 1
                ua = m.group(8)
                if ua is not None and is_bot_ua(ua):
                    a["bots"] += 1
                if n % 50000 == 0 and time.time() > deadline:
                    a["partial"] = True
                    break
            if a["partial"]:
                break
        if a["req"]:
            a["unique_ips"] = len(a["ips"])
            a["top_ips"] = a["ips"].most_common(5)
            ph = a["hours"].most_common(1)[0]
            a["peak_hour"], a["peak_hour_req"] = ph
            del a["ips"]
            per[name] = a
    if skipped:
        ctx.note("Traffic analysis time budget reached - %d smaller application(s) were not parsed "
                 "(raise --log-budget). Skipped: %s" % (len(skipped), ", ".join(skipped[:8]) + ("…" if len(skipped) > 8 else "")))
    if unreadable:
        ctx.note("%d web access log file(s) were not readable (run as root)." % unreadable)
    return {"per_app": per, "hour_req": hour_req, "hour_5xx": hour_5xx, "skipped": skipped}


def scan_fpm_access(ctx, start, end, deadline):
    """Per-application PHP-FPM access logs: PHP requests, CPU seconds, duration, memory per request."""
    hc = HourCache(start, end)
    per, hour_cpu = {}, Counter()
    sized = []
    for name, app in ctx.apps.items():
        files = files_for_window(app["fpm_access_logs"], start)
        sized.append((sum(os.path.getsize(f) for f in files if os.path.exists(f)), name, files))
    sized.sort(reverse=True)
    skipped = 0
    for size, name, files in sized:
        if not files:
            continue
        if time.time() > deadline:
            skipped += 1
            continue
        a = {"req": 0, "cpu_s": 0.0, "dur": 0.0, "slow5": 0, "slow30": 0, "mem_sum": 0.0, "mem_max": 0.0,
             "s5": 0, "max_dur": 0.0, "uri_cpu": defaultdict(lambda: [0, 0.0, 0.0])}
        n, stop = 0, False
        for f in files:
            if not os.access(f, os.R_OK):
                continue
            for line in iter_lines(f):
                m = FPM_ACCESS_RE.match(line)
                if not m:
                    continue
                flag, hk, base = hc.get(m.group(2), m.group(4))
                if flag == 0:
                    continue
                if flag == 2 and not in_window(base + timedelta(minutes=int(m.group(3))), start, end):
                    continue
                n += 1
                dur = float(m.group(8))
                cpu = dur * (float(m.group(10)) + float(m.group(11))) / 100.0
                mem = int(m.group(9)) / 1048576.0
                a["req"] += 1
                a["cpu_s"] += cpu
                a["dur"] += dur
                a["mem_sum"] += mem
                if mem > a["mem_max"]:
                    a["mem_max"] = mem
                if dur > a["max_dur"]:
                    a["max_dur"] = dur
                if dur >= 5:
                    a["slow5"] += 1
                    if dur >= 30:
                        a["slow30"] += 1
                if m.group(7)[0] == "5":
                    a["s5"] += 1
                hour_cpu[hk] += cpu
                uri = (m.group(12) or m.group(6)).split("?", 1)[0]
                u = a["uri_cpu"].get(uri)
                if u is None and len(a["uri_cpu"]) < 20000:
                    u = a["uri_cpu"][uri]
                if u is not None:
                    u[0] += 1
                    u[1] += cpu
                    u[2] += dur
                if n % 50000 == 0 and time.time() > deadline:
                    stop = True
                    break
            if stop:
                break
        if a["req"]:
            a["top_uris"] = sorted(((u, v[0], v[1], v[2] / v[0]) for u, v in a["uri_cpu"].items()),
                                   key=lambda x: -x[2])[:5]
            del a["uri_cpu"]
            per[name] = a
    if skipped:
        ctx.note("PHP-FPM access log time budget reached - %d application(s) not parsed (raise --log-budget)." % skipped)
    return {"per_app": per, "hour_cpu": hour_cpu}


def scan_slow_logs(ctx, start, end):
    """PHP slow-log traces per application with the plugin/theme most often on the stack."""
    per = {}
    for name, app in ctx.apps.items():
        files = [f for f in files_for_window(app["fpm_slow_logs"], start) if os.access(f, os.R_OK)]
        if not files:
            continue
        traces, comps, funcs, hours = 0, Counter(), Counter(), Counter()
        for f in files:
            active, got = False, False
            for line in iter_lines(f):
                h = SLOW_HEADER_RE.match(line)
                if h:
                    ts = make_ts(h.group(3), h.group(2), h.group(1), h.group(4), h.group(5), h.group(6))
                    active = in_window(ts, start, end)
                    got = False
                    if active:
                        traces += 1
                        hours[ts.strftime(HOUR_KEY)] += 1
                    continue
                if not active or got:
                    continue
                m = SLOW_FRAME_RE.match(line)
                if m and ("/wp-content/" in m.group(2) or "/app/code/" in m.group(2) or "/vendor/" in m.group(2)):
                    got = True
                    comps[component_of(m.group(2))] += 1
                    i = m.group(2).find("public_html/")
                    funcs["%s() %s:%s" % (m.group(1), m.group(2)[i + 12:] if i >= 0 else m.group(2), m.group(3))] += 1
        if traces:
            per[name] = {"traces": traces, "components": comps.most_common(4), "functions": funcs.most_common(3),
                         "hours": hours}
    return per


# ----------------------------------------------------------------------------
# MySQL / MariaDB
# ----------------------------------------------------------------------------
MY_STATUS = ("Threads_connected", "Threads_running", "Max_used_connections", "Slow_queries", "Aborted_connects",
             "Uptime", "Connection_errors_max_connections", "Created_tmp_disk_tables", "Innodb_buffer_pool_bytes_data")
MY_VARS = ("max_connections", "slow_query_log", "slow_query_log_file", "long_query_time", "datadir",
           "innodb_buffer_pool_size", "key_buffer_size", "tmp_table_size", "max_heap_table_size", "log_error",
           "version", "query_cache_size", "performance_schema")


def mysql_collect(ctx):
    res = {"available": False, "vars": {}, "status": {}}
    binp = shutil.which("mariadb") or shutil.which("mysql")
    if not binp:
        res["error"] = "mysql/mariadb client not found"
        return res
    base = [binp, "-N", "-B", "--connect-timeout=5"]
    if os.access("/root/.my.cnf", os.R_OK):
        base.insert(1, "--defaults-extra-file=/root/.my.cnf")
    rc, out, err = run_cmd(base + ["-e", "SELECT VERSION()"], 10)
    if rc != 0:
        last = err.strip().splitlines()[-1] if err.strip() else "unknown error"
        res["error"] = "cannot connect (%s)" % trunc(re.sub(r"'[^']*'@", "'***'@", last), 90)
        ctx.note("MySQL/MariaDB live data unavailable: %s. Run as root (uses /root/.my.cnf)." % res["error"])
        return res
    res["available"], res["version"] = True, out.strip()

    def kv(sql, keys):
        rc2, o2, _ = run_cmd(base + ["-e", sql], 15)
        return {r[0]: r[1] for r in (l.split("\t") for l in o2.splitlines()) if len(r) >= 2 and r[0] in keys}
    res["vars"] = kv("SHOW GLOBAL VARIABLES", MY_VARS)
    res["status"] = kv("SHOW GLOBAL STATUS", MY_STATUS)
    rc, out, _ = run_cmd(base + ["-e", "SELECT table_schema, ROUND(SUM(data_length+index_length)/1048576) FROM "
                                 "information_schema.TABLES GROUP BY table_schema ORDER BY 2 DESC LIMIT 8"], 30)
    if rc == 0:
        res["db_sizes"] = [(r[0], float(r[1])) for r in (l.split("\t") for l in out.splitlines())
                           if len(r) == 2 and r[1].replace(".", "").isdigit()
                           and r[0] not in ("information_schema", "performance_schema", "sys", "mysql")]
    return res


def my_slow_ts(line):
    m = MY_SLOW_TS_RE.match(line)
    if m:
        return datetime.fromtimestamp(int(m.group(1)))
    m = MY_SLOW_TIME_ISO_RE.match(line)
    if m:
        return make_ts(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), "Z" if m.group(7) else None)
    m = MY_SLOW_TIME_OLD_RE.match(line)
    if m:
        return make_ts(2000 + int(m.group(1)), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6))
    return None


def scan_mysql_slowlog(ctx, my, start, end):
    v = my.get("vars", {})
    path = v.get("slow_query_log_file") or ""
    if path and not path.startswith("/"):
        path = os.path.join(v.get("datadir", "/var/lib/mysql"), path)
    cands = ([path] if path else []) + ["/var/log/mysql/slow-query.log", "/var/log/mysql/mysql-slow.log",
                                        "/var/log/mysql/mariadb-slow.log"]
    files, used = [], ""
    for c in cands:
        if glob.glob(c + "*"):
            used = c
            files = files_for_window(c + "*", start)
            break
    res = {"file": used, "enabled": v.get("slow_query_log", "?"), "long_query_time": v.get("long_query_time", "?"),
           "total": 0, "by_db": {}, "by_day": Counter(), "by_hour": Counter(), "fingerprints": [], "dumps": 0}
    if not used:
        ctx.note("MySQL slow query log not found - slow-query history unavailable.")
        return res
    if files and not any(os.access(f, os.R_OK) for f in files):
        ctx.note("MySQL slow query log is not readable (run as root).")
        return res
    fps, by_db = {}, defaultdict(lambda: {"count": 0, "time": 0.0, "max": 0.0, "hours": Counter()})
    for f in files:
        state = {"cur": None, "sql": [], "ts": None, "user": "", "schema": ""}

        def flush(state=state):
            cur = state["cur"]
            if cur is None:
                return
            q = " ".join(state["sql"]).strip()
            ts = cur.get("ts") or state["ts"]
            state["cur"], state["sql"] = None, []
            if not q or not in_window(ts, start, end):
                return
            if "SQL_NO_CACHE" in q and "/*!40001" in q:
                res["dumps"] += 1
            db = cur["db"] or "(unknown)"
            fp = sql_fingerprint(q)
            a = fps.setdefault((db, fp), {"db": db, "fp": fp, "count": 0, "time": 0.0, "max": 0.0, "rows_ex": 0})
            a["count"] += 1
            a["time"] += cur["qt"]
            a["max"] = max(a["max"], cur["qt"])
            a["rows_ex"] += cur["re"]
            d = by_db[db]
            d["count"] += 1
            d["time"] += cur["qt"]
            d["max"] = max(d["max"], cur["qt"])
            d["hours"][ts.strftime(HOUR_KEY)] += 1
            res["total"] += 1
            res["by_day"][ts.strftime("%Y-%m-%d")] += 1
            res["by_hour"][ts.strftime("%Y-%m-%d %H")] += 1

        for line in iter_lines(f):
            if line.startswith("# Time:"):
                flush()
                state["ts"] = my_slow_ts(line)
            elif line.startswith("# User@Host:"):
                flush()
                m = MY_SLOW_USER_RE.match(line)
                state["user"], state["schema"] = (m.group(1) if m else ""), ""
            elif line.startswith("# Thread_id:") or line.startswith("# Schema:"):
                m = MY_SLOW_SCHEMA_RE.search(line)
                state["schema"] = m.group(1) if m else state["schema"]
            elif line.startswith("# Query_time:"):
                m = MY_SLOW_QT_RE.match(line)
                flush()
                if m:
                    state["cur"] = {"qt": float(m.group(1)), "re": int(m.group(4)), "ts": None,
                                    "db": state["schema"] or (state["user"] if state["user"] in ctx.apps else "")}
            elif line.startswith("#"):
                continue
            elif state["cur"] is not None:
                if line.startswith("SET timestamp="):
                    state["cur"]["ts"] = my_slow_ts(line)
                    continue
                mu = MY_SLOW_USE_RE.match(line)
                if mu:
                    state["cur"]["db"] = mu.group(1)
                    continue
                if line.startswith(("/usr/sbin/", "Tcp port:", "Time ")) and not state["sql"]:
                    continue
                if len(state["sql"]) < 100:
                    state["sql"].append(line.strip())
        flush()
    res["fingerprints"] = sorted(fps.values(), key=lambda x: -x["time"])[:10]
    res["by_db"] = dict(sorted(by_db.items(), key=lambda kv: -kv[1]["time"]))
    return res


def scan_mysql_errorlog(ctx, my, start, end):
    path = my.get("vars", {}).get("log_error") or ""
    cands = ([path] if path.startswith("/") else []) + ["/var/log/mysql/error.log", "/var/log/mysql/mariadb.err",
                                                         "/var/log/mysql.err", "/var/log/mysqld.log"]
    files = []
    for c in cands:
        if glob.glob(c + "*"):
            files = [f for f in files_for_window(c + "*", start) if os.access(f, os.R_OK)]
            if not files and not any(os.access(f, os.R_OK) for f in glob.glob(c + "*")):
                ctx.note("MySQL error log is not readable (run as root).")
            break
    res = {"startups": [], "crash_recovery": 0, "too_many_conn": 0, "crashed_tables": Counter(), "oom": 0,
           "aborted": 0, "errors": Counter(), "files": len(files)}
    ts = None
    for f in files:
        for line in iter_lines(f):
            m = MY_ERR_TS_RE.match(line)
            if m:
                ts = make_ts(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6), "Z" if m.group(7) else None)
            if not in_window(ts, start, end):
                continue
            low = line.lower()
            if "ready for connections" in low:
                if not res["startups"] or (ts - res["startups"][-1]).total_seconds() > 5:
                    res["startups"].append(ts)
            elif "starting crash recovery" in low or "crash recovery finished" in low or "was not shutdown normally" in low:
                res["crash_recovery"] += 1 if ("starting crash recovery" in low or "not shutdown normally" in low) else 0
            elif "too many connections" in low:
                res["too_many_conn"] += 1
            elif "marked as crashed" in low:
                t = re.search(r"[Tt]able '?([^' ]+)'? is marked as crashed", line)
                res["crashed_tables"][t.group(1) if t else "?"] += 1
            elif "out of memory" in low or "cannot allocate memory" in low:
                res["oom"] += 1
            elif "aborted connection" in low:
                res["aborted"] += 1
            elif "[error]" in low:
                msg = line.split("[ERROR]", 1)[-1] if "[ERROR]" in line else line
                res["errors"][trunc(re.sub(r"\d+", "N", msg.strip()), 110)] += 1
    return res


# ----------------------------------------------------------------------------
# Configuration review
# ----------------------------------------------------------------------------
def config_review(ctx, base, my, live):
    cfg = {"flags": [], "budget": []}
    ram_mb = base["ram_kb"] / 1024.0 or 1.0
    # Apache
    apache = {}
    for f in (glob.glob("/etc/apache2/mods-enabled/mpm_*.conf") + ["/etc/apache2/apache2.conf"]
              + glob.glob("/etc/apache2/conf-enabled/*.conf")):
        for m in re.finditer(r"^\s*(MaxRequestWorkers|MaxClients|ServerLimit|ThreadsPerChild|ThreadLimit|"
                             r"MaxConnectionsPerChild|StartServers)\s+(\d+)", read_text(f, 300000) or "", re.M):
            apache[m.group(1)] = max(apache.get(m.group(1), 0), int(m.group(2)))
    mpm = [os.path.basename(f)[4:-5] for f in glob.glob("/etc/apache2/mods-enabled/mpm_*.load")]
    cfg["apache"] = {"mpm": ", ".join(mpm) or "?", "values": apache}
    mrw = max(apache.get("MaxRequestWorkers", 0), apache.get("MaxClients", 0))
    if mrw >= 1000:
        cfg["flags"].append(("warning", "Apache MaxRequestWorkers=%d is far above what %s GB RAM can serve "
                             "(36000 is a known bad value) - Apache can spawn threads until memory runs out."
                             % (mrw, base["ram_gb"])))
    # PHP-FPM pools
    pools = [p for p in ctx.pools.values() if p.get("pm.max_children", "").isdigit()]
    total_children = sum(int(p["pm.max_children"]) for p in pools)
    limits = [to_mb(p.get("php_admin_value[memory_limit]") or p.get("php_value[memory_limit]")) for p in pools]
    limits = [l for l in limits if l]
    ini_limit = None
    for ini in sorted(glob.glob("/etc/php/*/fpm/php.ini"), reverse=True):
        m = re.search(r"^\s*memory_limit\s*=\s*(\S+)", read_text(ini, 500000) or "", re.M)
        if m:
            ini_limit = to_mb(m.group(1))
            break
    worker_mb = (live.get("fpm_worker_avg_kb") or 0) / 1024.0
    est_worker_mb = worker_mb if worker_mb >= 20 else 64.0
    cfg["fpm"] = {"pools": len(pools), "total_children": total_children,
                  "max_memory_limit_mb": max(limits) if limits else ini_limit, "ini_memory_limit_mb": ini_limit,
                  "worker_avg_mb": worker_mb or None, "est_worker_mb": est_worker_mb,
                  "worst_case_mb": total_children * est_worker_mb}
    if pools and cfg["fpm"]["worst_case_mb"] > ram_mb * 1.5:
        cfg["flags"].append(("warning", "PHP-FPM over-commit: %d pools allow %d workers in total; at ~%.0f MB per "
                             "worker that is %s worst case vs %s RAM (%.1fx)."
                             % (len(pools), total_children, est_worker_mb, fmt_kb(cfg["fpm"]["worst_case_mb"] * 1024),
                                fmt_kb(base["ram_kb"]), cfg["fpm"]["worst_case_mb"] / ram_mb)))
    ml = cfg["fpm"]["max_memory_limit_mb"]
    if ml and ml >= 512 and ml * 4 > ram_mb:
        cfg["flags"].append(("warning", "PHP memory_limit up to %.0f MB - four such requests alone exceed the "
                             "server RAM (%s)." % (ml, fmt_kb(base["ram_kb"]))))
    # MariaDB
    bp = to_mb(my.get("vars", {}).get("innodb_buffer_pool_size"))
    if bp is None:
        for f in glob.glob("/etc/mysql/**/*.cnf", recursive=True) + ["/etc/my.cnf"]:
            m = re.search(r"^\s*innodb[_-]buffer[_-]pool[_-]size\s*=\s*(\S+)", read_text(f, 300000) or "", re.M)
            if m:
                bp = to_mb(m.group(1))
    cfg["innodb_buffer_pool_mb"] = bp
    cfg["max_connections"] = my.get("vars", {}).get("max_connections")
    if bp:
        cfg["budget"].append(("MariaDB innodb_buffer_pool_size", bp))
        if bp > ram_mb * 0.5 and base["apps"] > 1:
            cfg["flags"].append(("warning", "innodb_buffer_pool_size %s is %.0f%% of RAM on a server that also runs "
                                 "PHP for %d apps." % (fmt_kb(bp * 1024), pct(bp, ram_mb), base["apps"])))
    # Redis
    redis = {}
    conf = read_text("/etc/redis/redis.conf", 500000) or ""
    rc, out, err = run_cmd(["redis-cli", "-h", "127.0.0.1", "INFO", "memory"], 5)
    if "NOAUTH" in out + err:
        m = re.search(r"^\s*requirepass\s+\"?([^\"\s]+)", conf, re.M)
        if m:       # password goes through the environment only: not visible in `ps`, never printed
            rc, out, err = run_cmd(["redis-cli", "-h", "127.0.0.1", "--no-auth-warning", "INFO", "memory"], 5,
                                   env=dict(os.environ, REDISCLI_AUTH=m.group(1)))
        else:
            ctx.note("Redis requires authentication and its config is not readable - Redis memory settings not checked.")
    if rc == 0 and "used_memory:" in out:
        kv = dict(l.strip().split(":", 1) for l in out.splitlines() if ":" in l)
        redis = {"used_mb": int(kv.get("used_memory", 0)) / 1048576.0, "maxmemory_mb": int(kv.get("maxmemory", 0)) / 1048576.0,
                 "policy": kv.get("maxmemory_policy", "")}
    else:
        m = re.search(r"^\s*maxmemory\s+(\S+)", conf, re.M)
        if m:
            redis = {"maxmemory_mb": to_mb(m.group(1)) or 0.0}
    cfg["redis"] = redis
    if redis:
        if redis.get("maxmemory_mb"):
            cfg["budget"].append(("Redis maxmemory", redis["maxmemory_mb"]))
        elif "maxmemory_mb" in redis:
            cfg["flags"].append(("warning", "Redis maxmemory is 0 (unlimited) - the cache can grow until the server "
                                 "runs out of memory."))
    # JVM / Varnish / Memcached limits from the running processes
    for p in live.get("all", []):
        cmd = p["cmd"]
        if p["comm"] == "java":
            m = re.search(r"-Xmx(\d+)([mMgG])", cmd)
            if m:
                heap = int(m.group(1)) * (1024 if m.group(2).lower() == "g" else 1)
                cfg["es_heap_mb"] = heap
                cfg["budget"].append(("Elasticsearch/OpenSearch heap (-Xmx)", heap))
                if heap > ram_mb * 0.5 or (base["ram_gb"] <= 8 and heap >= 2048):
                    cfg["flags"].append(("warning", "Elasticsearch/OpenSearch heap %s competes with MariaDB and PHP on "
                                         "%s GB RAM." % (fmt_kb(heap * 1024), base["ram_gb"])))
        elif p["comm"].startswith("varnishd") and "varnish_mb" not in cfg:
            m = re.search(r"malloc,(\d+)([kKmMgG])", cmd)
            if m:
                cfg["varnish_mb"] = to_mb(m.group(1) + m.group(2)) or 0
                cfg["budget"].append(("Varnish malloc", cfg["varnish_mb"]))
        elif p["comm"] == "memcached" and "memcached_mb" not in cfg:
            m = re.search(r"-m\s+(\d+)", cmd)
            if m:
                cfg["memcached_mb"] = int(m.group(1))
                cfg["budget"].append(("Memcached -m", int(m.group(1))))
    if pools:
        cfg["budget"].append(("PHP-FPM worst case (%d workers x ~%.0f MB)" % (total_children, est_worker_mb),
                              cfg["fpm"]["worst_case_mb"]))
    cfg["budget_total_mb"] = sum(v for _, v in cfg["budget"])
    # Swap / disk
    if not base["swap_kb"] and base["ram_kb"]:
        cfg["flags"].append(("info", "No swap configured - any memory spike goes straight to the OOM killer."))
    for fs in base["filesystems"]:
        if fs["used_pct"] >= 90 or fs["inode_pct"] >= 90:
            cfg["flags"].append(("critical" if max(fs["used_pct"], fs["inode_pct"]) >= 97 else "warning",
                                 "Filesystem %s is %.0f%% full (inodes %.0f%%) - a full disk stops MySQL writes, "
                                 "sessions and logs." % (fs["mount"], fs["used_pct"], fs["inode_pct"])))
    return cfg


# ----------------------------------------------------------------------------
# Analysis: findings, root cause, recommendations
# ----------------------------------------------------------------------------
def finding(sev, title, evidence=None, action=None, tag=None):
    return {"sev": sev, "title": title, "evidence": [e for e in (evidence or []) if e], "action": action, "tag": tag}


def oom_summary(ctx, R):
    events = R["sys"]["oom"]
    glob_ev = [e for e in events if not e["cgroup"]]
    by_proc = Counter(e["name"] for e in events)
    by_day = Counter(e["ts"].strftime("%Y-%m-%d") for e in events)
    by_hour = Counter(e["ts"].strftime("%Y-%m-%d %H") for e in events)
    hod = Counter(e["ts"].hour for e in events)
    holders = defaultdict(lambda: {"sum": 0, "peak": 0, "n": 0})
    dumps, share_sum = 0, defaultdict(float)
    for e in events:
        if not e["holders"] or not e["snap_total_kb"]:
            continue
        dumps += 1
        for kind, owner, kb in e["holders"]:
            h = holders[(kind, owner)]
            h["sum"] += kb
            h["peak"] = max(h["peak"], kb)
            h["n"] += 1
            share_sum[(kind, owner)] += pct(kb, e["snap_total_kb"])
    hold = [{"kind": k[0], "owner": k[1], "avg_kb": v["sum"] / dumps, "peak_kb": v["peak"],
             "share": share_sum[k] / dumps} for k, v in holders.items()] if dumps else []
    hold.sort(key=lambda h: -h["share"])
    swap_known = [e for e in events if e["swap_total_kb"]]
    swap_out = [e for e in swap_known if e["swap_free_kb"] is not None and e["swap_free_kb"] < e["swap_total_kb"] * 0.02]
    return {"total": len(events), "global": len(glob_ev), "cgroup": len(events) - len(glob_ev),
            "by_proc": by_proc.most_common(), "by_day": by_day, "by_hour": by_hour, "hod": hod,
            "holders": hold, "dumps": dumps, "swap_known": len(swap_known), "swap_exhausted": len(swap_out),
            "triggers": Counter(e["trigger"] for e in events if e["trigger"]).most_common(5),
            "peak_day": by_day.most_common(1)[0] if by_day else None,
            "app_share": sum(h["share"] for h in hold if h["kind"] == "app")}


def memory_driver(ctx, R, o):
    """What filled the memory. Returns (key, internal description, customer description)."""
    def app_desc(names):
        doms = [ctx.apps.get(n, {}).get("domain") or n for n in names]
        return ", ".join(doms[:3])
    hold = o["holders"]
    if hold:
        apps = [h for h in hold if h["kind"] == "app"]
        top = hold[0]
        if apps and apps[0]["share"] >= 25:
            a = apps[0]
            return ("app", "PHP-FPM workers of app %s held ~%.0f%% of memory at OOM time" % (a["owner"], a["share"]),
                    "PHP processes of the application %s" % app_desc([a["owner"]]))
        if o["app_share"] >= 40:
            names = [a["owner"] for a in apps[:3]]
            return ("apps", "PHP-FPM workers across applications held ~%.0f%% of memory at OOM time (top: %s)"
                    % (o["app_share"], ", ".join(names)),
                    "the combined PHP workload of the hosted applications (most notably %s)" % app_desc(names))
        if top["kind"] == "service" and top["share"] >= 25:
            if top["owner"] == "mysql" and top["share"] < 45:
                pass
            else:
                return (top["owner"], "%s held ~%.0f%% of memory at OOM time" % (top["owner"], top["share"]),
                        CUSTOMER_NAME.get(top["owner"], "background processes"))
        return ("combined", "no single holder dominated (top: %s)" % ", ".join(
            "%s %.0f%%" % (h["owner"], h["share"]) for h in hold[:3]),
            "the combined memory footprint of the services and applications on the server")
    at = R.get("atop")
    if at:
        apps = sorted((x for x in at["owners"] if x["kind"] == "app"), key=lambda x: -x["rss_peak_kb"])
        if apps and apps[0]["rss_peak_kb"] > R["base"]["ram_kb"] * 0.25:
            a = apps[0]
            return ("app", "app %s peaked at %s RSS (atop, %s)" % (a["owner"], fmt_kb(a["rss_peak_kb"]), a["rss_peak_at"]),
                    "PHP processes of the application %s" % app_desc([a["owner"]]))
    return ("combined", "kernel task dumps unavailable - driver inferred from victims only",
            "the combined memory footprint of the services and applications on the server")


def analyze(ctx, R):
    base, cfg, at = R["base"], R["config"], R.get("atop")
    o = oom_summary(ctx, R)
    R["oom"] = o
    F = []
    ram_gb, napps = base["ram_gb"], base["apps"]
    A = {"driver": None}

    # --- Memory / OOM
    if o["global"]:
        drv = memory_driver(ctx, R, o)
        A["driver"] = drv
        victims = ", ".join("%s (%d)" % (n, c) for n, c in o["by_proc"][:4])
        ev = ["%d OOM kill(s) in the window; victims: %s" % (o["total"], victims),
              "Peak day %s with %d kill(s)" % o["peak_day"] if o["peak_day"] else None,
              "Memory driver: " + drv[1],
              ("Swap was exhausted (<2%% free) in %d of %d kernel reports" % (o["swap_exhausted"], o["swap_known"]))
              if o["swap_known"] else None]
        F.append(finding("critical", "Server ran out of memory: %d OOM-killer event(s)" % o["global"], ev,
                         "Reduce the memory driver first (see optimizations); size MariaDB/Redis/PHP-FPM to the RAM "
                         "actually available.", "oom"))
    if o["cgroup"]:
        F.append(finding("warning", "%d cgroup-limited OOM kill(s) (a service hit its own memory limit, "
                         "not the whole server)" % o["cgroup"],
                         ["Victims: " + ", ".join("%s (%d)" % kv for kv in Counter(
                             e["name"] for e in R["sys"]["oom"] if e["cgroup"]).most_common(4))],
                         "Review the memory limit of the affected unit/container.", "oom-cgroup"))
    # --- Reboots
    rb = R["reboots"]
    if rb:
        unclean = [r for r in rb if r["clean"] is False]
        F.append(finding("critical" if unclean else "warning",
                         "%d reboot(s) in the window%s" % (len(rb), " (%d without a clean shutdown record)" % len(unclean) if unclean else ""),
                         ["%s - %s" % (r["ts"].strftime("%Y-%m-%d %H:%M:%S"),
                                       {True: "clean shutdown recorded", False: "NO shutdown record (crash, hard reset or provider-level event)",
                                        None: "shutdown record unknown"}[r["clean"]]) for r in rb[:6]],
                         "Match reboot times against platform actions (manual restart, vertical scaling, provider "
                         "maintenance) and the OOM timeline.", "reboot"))
    # --- Service failures
    se = R["sys"]["svc_events"]
    if se:
        per = Counter(e["unit"] for e in se)
        F.append(finding("warning", "%d service failure/auto-restart event(s) logged by systemd" % len(se),
                         ["%s: %d event(s)" % kv for kv in per.most_common(5)] +
                         ["%s %s: %s" % (e["ts"].strftime("%Y-%m-%d %H:%M:%S"), e["unit"], e["what"]) for e in se[:4]],
                         "Correlate with OOM kills above; a service killed by the OOM killer is a victim, not a cause.",
                         "service"))
    # --- CPU / memory history
    if at:
        share = pct(at["cpu_high"], at["intervals"])
        topc = sorted(at["owners"], key=lambda x: -x["cpu_avg"])[:3]
        topdesc = ", ".join("%s %.0f%%" % (owner_label(ctx, x["kind"], x["owner"]), x["cpu_avg"]) for x in topc)
        if at["cpu_avg"] >= 80 or share >= 25:
            F.append(finding("critical", "Sustained CPU saturation (avg %.0f%%, peak %.0f%%)" % (at["cpu_avg"], at["cpu_peak"]),
                             ["%d of %d atop intervals (%.0f%%) at >= 85%% busy" % (at["cpu_high"], at["intervals"], share),
                              "Top CPU consumers (%% of one core, window avg): " + topdesc],
                             "Optimise the top consumer; upscale vCPUs only if the load is legitimate traffic.", "cpu"))
        elif at["cpu_avg"] >= 60 or share >= 10:
            F.append(finding("warning", "Elevated CPU usage (avg %.0f%%, peak %.0f%%)" % (at["cpu_avg"], at["cpu_peak"]),
                             ["%d of %d atop intervals at >= 85%% busy" % (at["cpu_high"], at["intervals"]),
                              "Top CPU consumers (% of one core, window avg): " + topdesc],
                             "Review the top consumer's slow requests and cron activity.", "cpu"))
        if at["mem_avg"] >= 88 or pct(at["mem_high"], at["intervals"]) >= 20:
            F.append(finding("warning", "Memory persistently high (avg %.0f%%, peak %.0f%% used)" % (at["mem_avg"], at["mem_peak"]),
                             ["%d of %d atop intervals at >= 90%% used" % (at["mem_high"], at["intervals"]),
                              "Swap peak %s of %s" % (fmt_kb(at["swap_peak_kb"]), fmt_kb(base["swap_kb"]))],
                             "Little headroom for traffic or cron spikes - tune memory consumers or add RAM.", "mem"))
        if at["steal"] >= 8:
            F.append(finding("warning", "High CPU steal (avg %.1f%%) - the hypervisor is withholding CPU" % at["steal"], [],
                             "Provider-level contention; consider migrating/resizing the instance.", "steal"))
        if at["iowait"] >= 15:
            F.append(finding("warning", "High I/O wait (avg %.1f%%) - disk is a bottleneck" % at["iowait"], [],
                             "Check swap thrashing, backups and heavy DB writes in the same window.", "io"))
    # --- Configuration
    for sev, text in cfg["flags"]:
        F.append(finding(sev, text, [], None, "config"))
    # --- PHP-FPM
    fpm = R["fpm"]["per_app"]
    mc = sorted(((a, v) for a, v in fpm.items() if v["max_children"]), key=lambda kv: -kv[1]["max_children"])
    if mc:
        F.append(finding("warning", "PHP-FPM pm.max_children reached %d time(s) across %d app(s)"
                         % (sum(v["max_children"] for _, v in mc), len(mc)),
                         ["%s: %d time(s) (limit %s)" % (a, v["max_children"], v["limit"]) for a, v in mc[:5]],
                         "Find what keeps workers busy (slow PHP, slow SQL, external calls) before raising the limit.",
                         "fpm"))
    sk = sum(v["sigkill"] for v in fpm.values())
    if sk:
        F.append(finding("warning", "%d PHP-FPM worker(s) died on SIGKILL (typically the OOM killer)" % sk,
                         ["%s: %d" % (a, v["sigkill"]) for a, v in sorted(fpm.items(), key=lambda kv: -kv[1]["sigkill"])[:4] if v["sigkill"]],
                         None, "fpm"))
    pa = R["phpacc"]["per_app"]
    heavy = sorted(pa.items(), key=lambda kv: -kv[1]["cpu_s"])[:1]
    if heavy and heavy[0][1]["req"] >= 50:
        name, v = heavy[0]
        tot_cpu = sum(x["cpu_s"] for x in pa.values()) or 1
        if pct(v["cpu_s"], tot_cpu) >= 50 and (v["slow5"] >= 20 or v["cpu_s"] / v["req"] >= 0.4):
            F.append(finding("warning", "Application %s dominates PHP CPU time (%.0f%% of all PHP CPU)"
                             % (name, pct(v["cpu_s"], tot_cpu)),
                             ["%s PHP requests, %s CPU-seconds, %.0f ms CPU/request" % (fmt_num(v["req"]), fmt_num(round(v["cpu_s"])), v["cpu_s"] / v["req"] * 1000),
                              "%d request(s) >= 5s, %d >= 30s; avg memory %.0f MB/request" % (v["slow5"], v["slow30"], v["mem_sum"] / v["req"])],
                             "Profile the slow paths and plugins of this application (see PHP-FPM section).", "app"))
            A["heavy_app"] = name
    # --- Database
    sl, el = R["mysql_slow"], R["mysql_err"]
    if sl["total"] >= 50:
        topdb = list(sl["by_db"].items())[:3]
        F.append(finding("warning", "%s slow queries (>= %ss) in the window" % (fmt_num(sl["total"]), sl["long_query_time"]),
                         ["%s: %d queries, %.0fs total, max %.1fs" % (db, d["count"], d["time"], d["max"]) for db, d in topdb],
                         "Review the top query fingerprints with the developer (indexes, autoloaded options, object cache).",
                         "db"))
    if el["crash_recovery"] or len(el["startups"]) > 1:
        F.append(finding("warning", "MariaDB/MySQL restarted %d time(s) in the window (%d crash recoveries)"
                         % (len(el["startups"]), el["crash_recovery"]),
                         ["Startups: " + ", ".join(t.strftime("%m-%d %H:%M") for t in el["startups"][:8])],
                         "Each restart drops every site's connections; match the startup times against OOM kills "
                         "and platform actions.", "db-restart"))
    if el["too_many_conn"]:
        F.append(finding("warning", "'Too many connections' logged %d time(s)" % el["too_many_conn"], [],
                         "Usually a symptom of slow queries/PHP piling up, not of a low max_connections.", "db-conn"))
    if el["crashed_tables"]:
        F.append(finding("warning", "Tables marked as crashed: " + ", ".join(list(el["crashed_tables"])[:5]), [],
                         "Repair the tables; crashed tables commonly follow an unclean MariaDB kill.", "db-tables"))
    # --- Traffic
    tr = R["traffic"]
    A["traffic"] = traffic_assessment(ctx, R)
    ta = A["traffic"]
    if ta["req"]:
        if ta["rate5"] >= 5 and ta["s5"] >= 100:
            F.append(finding("warning", "Elevated 5xx error rate: %s responses (%.1f%% of requests)" % (fmt_num(ta["s5"]), ta["rate5"]),
                             ["Worst hours: " + ", ".join("%s:00 (%d)" % kv for kv in tr["hour_5xx"].most_common(4))],
                             "5xx bursts line up with OOM kills / worker exhaustion - check the timeline.", "traffic"))
        for s in ta["signals"]:
            F.append(finding("warning" if ta["strong"] else "info", s, [],
                             "Verify the client is expected; rate-limit or block at the edge (Cloudflare / bot "
                             "protection) if it is not.", "traffic"))
    # --- Imunify (internal)
    im = imunify_summary(ctx, R, o)
    A["imunify"] = im
    if im["relevant"]:
        F.append(finding("warning", "[INTERNAL] Imunify contributed to resource pressure", im["evidence"],
                         "See the internal Imunify note; never share with the customer.", "imunify"))
    F.sort(key=lambda f: SEV_ORDER[f["sev"]])
    A["findings"] = F

    # --- Root cause
    tags = {}
    for f in F:
        if f["sev"] != "info":
            tags.setdefault(f["tag"], f)
    disk_full = [f for f in F if f["tag"] == "config" and f["sev"] == "critical" and "Filesystem" in f["title"]]
    if disk_full:
        rc = ("Disk space exhausted", "Confirmed")
    elif o["global"]:
        rc = ("Memory exhaustion - the kernel OOM killer terminated services (%d kill(s))" % o["global"], "Confirmed")
    elif "cpu" in tags and tags["cpu"]["sev"] == "critical":
        rc = ("CPU saturation", "Confirmed")
    elif rb:
        rc = ("Server reboot(s) without an in-OS cause logged (manual, platform or provider-level)", "Likely")
    elif se:
        rc = ("Service instability (%s)" % ", ".join(sorted({e["unit"] for e in se})[:3]), "Likely")
    elif not R["sys"]["checked"]:
        rc = ("Inconclusive - kernel/system logs were not readable, so OOM kills and crashes could not be ruled "
              "out (run as root)", "Unknown")
    elif "db-restart" in tags and el["crash_recovery"]:
        rc = ("Database service crashed and recovered (%d crash recoveries) without a logged OOM kill" % el["crash_recovery"], "Likely")
    elif "fpm" in tags or "db" in tags or "app" in tags:
        rc = ("Application-level bottleneck (PHP workers / database queries), not a server fault", "Likely")
    elif "traffic" in tags:
        rc = ("Traffic anomaly", "Suspected")
    else:
        rc = ("No server-level incident found in the window", "Confirmed" if at else "Likely")
    A["root_cause"], A["confidence"] = rc
    contrib = []
    for t, label in (("cpu", "CPU pressure"), ("fpm", "PHP-FPM worker saturation"), ("db", "slow database queries"),
                     ("db-restart", "database restarts"), ("config", "configuration red flags"),
                     ("traffic", "traffic anomalies")):
        if t in tags and not (t == "cpu" and rc[0].startswith("CPU")):
            contrib.append(label)
    A["contributing"] = contrib

    # --- Optimizations
    opt = []
    cfg_text = " ".join(f["title"] for f in F if f["tag"] == "config")
    drv_key = A["driver"][0] if A["driver"] else None
    if drv_key in ("app", "apps") or A.get("heavy_app"):
        target = A.get("heavy_app") or (o["holders"] and next((h["owner"] for h in o["holders"] if h["kind"] == "app"), None))
        opt.append("Optimise the heaviest application%s: profile slow requests, heavy plugins and WP-Cron/Action "
                   "Scheduler jobs; enable full-page + object caching."
                   % (" (%s)" % (ctx.apps.get(target, {}).get("domain") or target) if target else ""))
    if "PHP-FPM over-commit" in cfg_text or drv_key in ("app", "apps"):
        opt.append("Right-size PHP-FPM: lower pm.max_children on low-traffic apps so the total fits RAM "
                   "(currently %d workers allowed), and keep memory_limit at 256M unless an app proves it needs more."
                   % cfg["fpm"]["total_children"])
    if "Apache MaxRequestWorkers" in cfg_text:
        opt.append("[INTERNAL] Fix Apache MPM limits (MaxRequestWorkers / ServerLimit) to a value the RAM can serve.")
    if "innodb_buffer_pool_size" in cfg_text or drv_key == "mysql":
        opt.append("Resize innodb_buffer_pool_size to roughly 25-40% of RAM on this shared web+DB server.")
    if "Redis maxmemory" in cfg_text:
        opt.append("Set a Redis maxmemory limit with an eviction policy (allkeys-lru / allkeys-lfu).")
    if "Elasticsearch" in cfg_text or drv_key == "elasticsearch":
        opt.append("Cap the Elasticsearch/OpenSearch heap, or move search to its own server.")
    if "db" in tags and sl["total"] >= 50:
        opt.append("Fix the top slow-query fingerprints (indexes, autoloaded wp_options, object cache) on %s."
                   % ", ".join(list(sl["by_db"])[:2]))
    if "fpm" in tags and not any("PHP-FPM" in x for x in opt):
        opt.append("Resolve PHP worker exhaustion on %s by fixing slow execution before raising pm.max_children."
                   % ", ".join(ctx.apps.get(a, {}).get("domain") or a for a, _ in mc[:3]))
    if ta["strong"] or (ta["signals"] and ta["rate5"] >= 5):
        opt.append("Rate-limit abusive clients / aggressive bots at the edge (Cloudflare, bot protection, wp-login and xmlrpc rules).")
    if "Filesystem" in cfg_text:
        opt.append("Free disk space / inodes (old backups, logs, cache directories) and add monitoring.")
    if "No swap" in cfg_text and o["global"]:
        opt.append("Add swap as a safety net so short spikes do not immediately trigger the OOM killer.")
    if im["relevant"]:
        opt.append("[INTERNAL] Tune Imunify scan scheduling/resource limits (see internal note).")
    if not opt:
        opt.append("No change required from this window; keep monitoring.")
    A["optimizations"] = opt

    # --- Upscale decision
    nxt = next((t for t in RAM_TIERS_GB if t > ram_gb), ram_gb * 2) if ram_gb else "the next plan size"
    def size(v):
        return "%s GB" % v if isinstance(v, int) else v
    cfg_wrong = any(k in cfg_text for k in ("Apache MaxRequestWorkers", "innodb_buffer_pool_size", "Redis maxmemory",
                                            "Elasticsearch"))
    if ram_gb <= 4 and napps >= 30:
        up = ("Yes", "16 GB", "%d apps on %s GB is undersized regardless of tuning - urgent." % (napps, ram_gb))
    elif ram_gb <= 8 and napps >= 30:
        up = ("Yes", "16 GB", "%d apps on %s GB leaves no headroom per app." % (napps, ram_gb))
    elif o["global"]:
        if cfg_wrong and ram_gb >= 16:
            up = ("No", "", "RAM is adequate but the configuration is wrong - tune first, then re-check.")
        elif o["global"] >= 10 or (at and at["mem_avg"] >= 85):
            up = ("Yes", size(nxt), "%d OOM kills with%s sustained memory pressure - tuning alone is unlikely to "
                  "be enough." % (o["global"], "" if at and at["mem_avg"] >= 85 else " repeated"))
        else:
            up = ("Optional", size(nxt), "Few OOM kills - apply the optimizations first; upscale if they recur.")
    elif "cpu" in tags and tags["cpu"]["sev"] == "critical":
        up = ("Optional", "next vCPU tier", "CPU is saturated; optimise the top consumer first, upscale if the load is "
              "legitimate traffic.")
    else:
        up = ("No", "", "No capacity-driven incident in this window.")
    A["upscale"] = up
    A["incident_hours"] = incident_hours(R, o)
    A["top_apps"] = top_apps(ctx, R, 3)
    A["verdict"] = build_verdict(ctx, R, A, o)
    A["customer"] = customer_paragraph(ctx, R, A, o)
    A["customer_short"] = customer_paragraph(ctx, R, A, o, with_recs=False)
    R["analysis"] = A
    return A


def incident_hours(R, o):
    """Hours (YYYY-MM-DD HH) with an outage signal: OOM kills, reboots, service failures, DB restarts, 5xx bursts."""
    hrs = set(o["by_hour"])
    hrs.update(r["ts"].strftime(HOUR_KEY) for r in R["reboots"])
    hrs.update(e["ts"].strftime(HOUR_KEY) for e in R["sys"]["svc_events"])
    hrs.update(t.strftime(HOUR_KEY) for t in R["mysql_err"]["startups"])
    tr = R["traffic"]
    for hk, c in tr["hour_5xx"].items():
        if c >= 20 and pct(c, tr["hour_req"].get(hk, 0)) >= 10:
            hrs.add(hk)
    return sorted(hrs)


def traffic_floor(base):
    """Requests/hour at which traffic starts to matter for a server of this size.

    About 1,500 requests/hour per GB of RAM (minimum 3,000): 3,000 on 1-2 GB, 12,000 on 8 GB, 48,000 on 32 GB.
    Below it, a busy hour, a prominent client or a high bot share cannot load the server and is not flagged.
    """
    try:
        ram = float(base.get("ram_gb") or 0)
    except (TypeError, ValueError):
        ram = 0.0
    return int(max(3000, 1500 * ram))


def traffic_assessment(ctx, R):
    tr = R["traffic"]
    per = tr["per_app"]
    req = sum(a["req"] for a in per.values())
    s5 = sum(a["s5"] for a in per.values())
    bots = sum(a["bots"] for a in per.values())
    hours = sorted(tr["hour_req"].values())
    median = hours[len(hours) // 2] if hours else 0
    peak = tr["hour_req"].most_common(1)[0] if tr["hour_req"] else ("", 0)
    own = set(R["base"]["ips"]) | {"127.0.0.1", "::1"}
    window_h = max((R["meta"]["end"] - R["meta"]["start"]).total_seconds() / 3600.0, 0.02)
    floor = traffic_floor(R["base"])
    per_hour = req / window_h
    level = "low" if per_hour < floor / 10.0 else ("moderate" if per_hour < floor else "high")
    abuse = max(1000, floor // 10)
    signals = []
    for name, a in per.items():
        if a["login"] >= abuse:
            signals.append("%s wp-login.php requests on %s (possible brute force)" % (fmt_num(a["login"]), name))
        if a["xmlrpc"] >= abuse:
            signals.append("%s xmlrpc.php requests on %s (possible abuse)" % (fmt_num(a["xmlrpc"]), name))
        if a["req"] < 2000 or a["req"] / window_h < floor / 20.0:
            continue        # too little volume to load a server of this size
        for ip, n in a["top_ips"][:2]:
            if ip not in own and pct(n, a["req"]) >= 25:
                signals.append("Single IP %s sent %.0f%% of %s's requests (%s)" % (ip, pct(n, a["req"]), name, fmt_num(n)))
        if pct(a["bots"], a["req"]) >= 40:
            signals.append("Bots/tools are %.0f%% of %s's requests" % (pct(a["bots"], a["req"]), name))
    spike = bool(median and peak[1] >= max(median * 6, floor))
    strong = spike or any(("wp-login" in x or "xmlrpc" in x) for x in signals)
    if spike:
        signals.append("Traffic spike: %s requests in the hour %s:00 vs a median of %s/hour"
                       % (fmt_num(peak[1]), peak[0], fmt_num(median)))
    size = ("a %s GB server" % R["base"]["ram_gb"]) if R["base"].get("ram_gb") else "this server"
    volume = ("%s requests/day on average (%.2f per second) - %s for %s; traffic is only flagged from about %s "
              "requests/hour" % (fmt_num(int(round(per_hour * 24))), per_hour / 3600.0, level, size, fmt_num(floor)))
    if not req:
        ddos = "Not assessed - no web access logs could be read for the window."
    elif spike and any("Single IP" in s for s in signals):
        ddos = "Possible abusive traffic: a traffic spike coincides with a dominant client IP - review before ruling out."
    elif strong:
        ddos = "No DDoS pattern; some abusive/bot traffic was observed (see signals)."
    elif signals:
        ddos = "No DDoS pattern; one client or bot group is prominent (see signals) - verify it is expected."
    else:
        ddos = "No DDoS or attack pattern: traffic volume is %s for %s and no client dominates." % (level, size)
    return {"req": req, "s5": s5, "rate5": pct(s5, req), "bots": bots, "bot_share": pct(bots, req), "median_hour": median,
            "peak_hour": peak, "signals": signals[:8], "ddos": ddos, "spike": spike, "strong": strong,
            "level": level, "floor": floor, "per_day": per_hour * 24, "volume": volume}


def imunify_summary(ctx, R, o):
    kills = sum(c for n, c in o["by_proc"] if classify(ctx, n)[1] == "imunify")
    hold = next((h for h in o["holders"] if h["owner"] == "imunify"), None)
    at = R.get("atop")
    hist = next((x for x in at["owners"] if x["owner"] == "imunify"), None) if at else None
    live = next((g for k, g in R["live"]["groups"] if k[1] == "imunify"), None)
    ev = []
    if kills:
        ev.append("%d of %d OOM kills hit Imunify processes (%.0f%%)" % (kills, o["total"], pct(kills, o["total"])))
    if hold:
        ev.append("Imunify held avg %s (%.0f%% of memory) at OOM time, peak %s" % (fmt_kb(hold["avg_kb"]), hold["share"], fmt_kb(hold["peak_kb"])))
    if hist:
        ev.append("atop: CPU avg %.0f%% / peak %.0f%% of one core (%s); RSS avg %s / peak %s"
                  % (hist["cpu_avg"], hist["cpu_peak"], hist["cpu_peak_at"], fmt_kb(hist["rss_avg_kb"]), fmt_kb(hist["rss_peak_kb"])))
    if live:
        ev.append("Right now: %d process(es), %s RSS" % (live["n"], fmt_kb(live["rss_kb"])))
    relevant = bool(kills or (hold and hold["share"] >= 15) or (hist and (hist["cpu_avg"] >= 20 or hist["rss_peak_kb"] >= R["base"]["ram_kb"] * 0.2)))
    names = Counter(n for n, c in o["by_proc"] if classify(ctx, n)[1] == "imunify")
    return {"relevant": relevant, "evidence": ev, "kills": kills, "agents": list(names)}


def build_verdict(ctx, R, A, o):
    b = R["base"]
    if o["global"]:
        return ("%d OOM kills on a %s GB / %d-app server; %s. Upscale: %s%s."
                % (o["global"], b["ram_gb"], b["apps"], A["driver"][1], A["upscale"][0],
                   " to " + A["upscale"][1] if A["upscale"][1] else ""))
    return "%s (%s). Upscale: %s%s." % (A["root_cause"], A["confidence"], A["upscale"][0],
                                        " to " + A["upscale"][1] if A["upscale"][1] else "")


def customer_paragraph(ctx, R, A, o, with_recs=True):
    """Plain-language summary. Never mentions internal security tooling."""
    b, at, ta = R["base"], R.get("atop"), A["traffic"]
    w = R["meta"]
    period = "between %s and %s" % (w["start"].strftime("%b %d, %H:%M"), w["end"].strftime("%b %d, %H:%M"))
    s = []
    if A["root_cause"].startswith("Disk"):
        s.append("We reviewed the server %s and found that the disk ran out of free space, which prevents the "
                 "database and applications from writing data and causes errors or downtime." % period)
    elif o["global"]:
        victims = {classify(ctx, n)[1] if classify(ctx, n)[0] == "service" else "php-fpm" for n, _ in o["by_proc"][:3]}
        vict = "the database service" if "mysql" in victims else CUSTOMER_NAME.get(next(iter(victims)), "running services")
        s.append("We reviewed the server %s and found that it repeatedly ran out of available memory (%d "
                 "out-of-memory event%s%s)." % (period, o["global"], "s" if o["global"] != 1 else "",
                                                 ", most of them on %s" % datetime.strptime(o["peak_day"][0], "%Y-%m-%d").strftime("%b %d")
                                                 if o["peak_day"] and len(o["by_day"]) > 1 else ""))
        s.append("When memory is exhausted the operating system stops a running service to protect itself - in this "
                 "case mostly %s - which makes the websites slow or briefly unavailable until the service restarts "
                 "automatically." % vict)
        s.append("The memory pressure was driven mainly by %s." % A["driver"][2])
    elif A["root_cause"].startswith("CPU"):
        top = sorted((x for x in at["owners"] if x["owner"] != "imunify"), key=lambda x: -x["cpu_avg"])[:1] if at else []
        who = ""
        if top and top[0]["kind"] == "app":
            who = " The largest share of processing time was used by the application %s." % (
                ctx.apps.get(top[0]["owner"], {}).get("domain") or top[0]["owner"])
        s.append("We reviewed the server %s and found that its processors were fully utilised for long periods "
                 "(average %.0f%%, peaks of %.0f%%), which slows every website hosted on it.%s"
                 % (period, at["cpu_avg"], at["cpu_peak"], who))
    elif A["root_cause"].startswith("Server reboot"):
        s.append("We reviewed the server %s and found %d server restart(s) during this period; the websites were "
                 "unavailable while the server was starting up. The system logs do not show a fault inside the "
                 "server that caused the restart." % (period, len(R["reboots"])))
    elif A["root_cause"].startswith("Application-level"):
        s.append("We reviewed the server %s. The server itself remained healthy, but some application requests "
                 "took a long time to complete (slow PHP execution and/or slow database queries), which can make "
                 "the affected website slow or return errors under load." % period)
    elif A["root_cause"].startswith("Inconclusive"):
        s.append("We reviewed the server %s. The review is not yet conclusive because part of the system logs "
                 "could not be read; a complete analysis will follow." % period)
    elif A["root_cause"].startswith("Database service crashed"):
        s.append("We reviewed the server %s and found that the database service stopped unexpectedly and recovered "
                 "automatically %d time(s); while it restarts, websites cannot reach their data and may show errors."
                 % (period, len(R["mysql_err"]["startups"])))
    elif A["root_cause"].startswith("No server-level"):
        s.append("We reviewed the server %s and did not find a server-level incident: there were no out-of-memory "
                 "events, unexpected restarts or service crashes, and resource usage stayed within normal limits." % period)
    else:
        s.append("We reviewed the server %s. %s." % (period, A["root_cause"]))
    if ta["req"]:
        if ta["signals"] and ("Possible abusive" in ta["ddos"]):
            s.append("We also noticed unusual traffic from a small number of sources, which we recommend limiting.")
        elif ta["signals"]:
            s.append("We found no evidence of a DDoS attack or of the server being compromised.")
        else:
            s.append("We found no evidence of a DDoS attack or of the server being compromised; traffic levels were "
                     "consistent with normal activity.")
    if not with_recs:
        return " ".join(s)
    recs = [x for x in A["optimizations"] if not x.startswith("[INTERNAL]") and not x.startswith("No change")]
    up = A["upscale"]
    if recs:
        s.append("To stabilise the server we recommend the following: " + " ".join(
            "(%d) %s" % (i, r.split(":")[0].rstrip(".") + ".") for i, r in enumerate(recs[:3], 1)))
    if up[0] == "Yes":
        s.append("We also recommend upgrading the server to %s so it has enough capacity for the current workload." % up[1])
    elif up[0] == "Optional":
        s.append("If the issue recurs after these changes, upgrading the server to %s would provide additional headroom." % up[1])
    return " ".join(s)


# ----------------------------------------------------------------------------
# Report rendering
# ----------------------------------------------------------------------------
def app_traffic_status(ctx, R, name):
    """Traffic verdict for one application: Normal / Elevated errors / Needs review, with the reasons."""
    a = R["traffic"]["per_app"].get(name)
    if not a:
        return {"status": "No data", "flags": [], "detail": "no web access log data for the window", "req": 0}
    own = set(R["base"]["ips"]) | {"127.0.0.1", "::1"}
    hours = sorted(a["hours"].values())
    median = hours[len(hours) // 2]
    window_h = max((R["meta"]["end"] - R["meta"]["start"]).total_seconds() / 3600.0, 0.02)
    floor = traffic_floor(R["base"])
    busy = a["req"] >= 2000 and a["req"] / window_h >= floor / 20.0     # enough volume to matter on this server
    abuse = max(1000, floor // 10)
    flags, errors = [], False
    if a["s5"] >= 20 and pct(a["s5"], a["req"]) >= 5:
        errors = True
        flags.append("%.0f%% of responses are 5xx errors" % pct(a["s5"], a["req"]))
    if busy and pct(a["bots"], a["req"]) >= 40:
        flags.append("%.0f%% of requests come from bots/tools" % pct(a["bots"], a["req"]))
    ext = [(ip, n) for ip, n in a["top_ips"] if ip not in own]
    if busy and ext and pct(ext[0][1], a["req"]) >= 25:
        flags.append("one IP (%s) sends %.0f%% of requests" % (ext[0][0], pct(ext[0][1], a["req"])))
    if a["login"] >= abuse:
        flags.append("%s wp-login.php requests" % fmt_num(a["login"]))
    if a["xmlrpc"] >= abuse:
        flags.append("%s xmlrpc.php requests" % fmt_num(a["xmlrpc"]))
    if len(hours) >= 6 and a["peak_hour_req"] >= max(median * 6, 1000, floor // 4):
        flags.append("spike of %s requests at %s:00 (median %s/hour)" % (fmt_num(a["peak_hour_req"]), a["peak_hour"], fmt_num(median)))
    status = "Normal" if not flags else ("Elevated errors" if errors and len(flags) == 1 else "Needs review")
    return {"status": status, "flags": flags, "req": a["req"], "per_hour": a["req"] / window_h, "floor": floor,
            "peak_hour": a["peak_hour"], "peak_hour_req": a["peak_hour_req"], "unique_ips": a["unique_ips"],
            "s5_pct": pct(a["s5"], a["req"]), "bot_pct": pct(a["bots"], a["req"]),
            "detail": "%s requests (%s/hour avg, peak %s at %s:00), %s IPs, 5xx %.1f%%, bots %.0f%%"
                      % (fmt_num(a["req"]), fmt_num(int(round(a["req"] / window_h))), fmt_num(a["peak_hour_req"]),
                         a["peak_hour"][5:], fmt_num(a["unique_ips"]), pct(a["s5"], a["req"]), pct(a["bots"], a["req"]))}


def top_apps(ctx, R, n=3):
    """Applications ranked by combined CPU and memory share of the server, each with its traffic status."""
    at, base, pa = R.get("atop"), R["base"], R["phpacc"]["per_app"]
    window_s = max((R["meta"]["end"] - R["meta"]["start"]).total_seconds(), 1.0)
    hist = {x["owner"]: x for x in at["owners"] if x["kind"] == "app"} if at else {}
    live = {k[1]: g for k, g in R["live"]["groups"] if k[0] == "app"}
    ram_kb, ncpu = base["ram_kb"] or 1, base["ncpu"] or 1
    rows = []
    for name in set(hist) | set(pa) | set(live) | set(R["traffic"]["per_app"]):
        h, v = hist.get(name), pa.get(name)
        r = {"app": name, "domain": ctx.apps.get(name, {}).get("domain") or "", "type": ctx.apps.get(name, {}).get("type", "?"),
             "cpu_peak": None, "cpu_peak_at": "", "mem_avg_kb": None, "mem_peak_kb": None}
        if h:
            r.update(cpu_avg=h["cpu_avg"], cpu_peak=h["cpu_peak"], cpu_peak_at=h["cpu_peak_at"], cpu_src="atop history",
                     mem_avg_kb=h["rss_avg_kb"], mem_peak_kb=h["rss_peak_kb"], mem_src="atop history")
        else:
            r.update(cpu_avg=(v["cpu_s"] / window_s * 100.0) if v else 0.0,
                     cpu_src="PHP-FPM access log (estimated)" if v else "n/a")
            if name in live:
                r.update(mem_avg_kb=live[name]["rss_kb"], mem_src="live (now)")
            else:
                r["mem_src"] = "n/a"
        r["srv_pct"] = r["cpu_avg"] / ncpu
        r["mem_pct"] = pct(r["mem_avg_kb"] or 0, ram_kb) if base["ram_kb"] else 0.0
        r["php_req"] = v["req"] if v else None
        r["ms_req"] = (v["cpu_s"] / v["req"] * 1000.0) if v and v["req"] else None
        r["mb_req"] = (v["mem_sum"] / v["req"]) if v and v["req"] else None
        r["slow5"] = v["slow5"] if v else None
        r["traffic"] = app_traffic_status(ctx, R, name)
        r["score"] = r["srv_pct"] + r["mem_pct"]
        rows.append(r)
    rows.sort(key=lambda r: (-r["score"], -(r["traffic"]["req"])))
    rows = rows[:n]
    for r in rows:
        t = r["traffic"]
        heavy = r["srv_pct"] >= 15 or r["mem_pct"] >= 15
        if t["status"] == "No data":
            ins = "Traffic could not be measured, so resource use cannot be matched to load."
        elif t["status"] == "Normal" and heavy:
            ins = ("High resource use while traffic is normal - this points to inefficient application execution "
                   "(code, plugins, scheduled tasks), not to visitor load.")
        elif t["status"] == "Elevated errors" and heavy:
            ins = ("High resource use with normal visitor volume, and %s - the errors are a symptom of the "
                   "overload, not a traffic problem." % t["flags"][0])
        elif t["status"] == "Elevated errors":
            ins = "Resource use is modest and visitor volume is normal, but %s - check the application error log." % t["flags"][0]
        elif t["status"] != "Normal" and heavy:
            ins = "High resource use coincides with a traffic issue (%s) - address the traffic first." % "; ".join(t["flags"][:2])
        elif t["status"] != "Normal":
            ins = "Resource use is low, but traffic needs attention (%s)." % "; ".join(t["flags"][:2])
        else:
            ins = "Resource use is modest and traffic is normal - not a driver of the incident."
        if (r["ms_req"] or 0) >= 400:
            ins += " PHP is expensive per request (%.0f ms CPU on average)." % r["ms_req"]
        r["insight"] = ins
    return rows


def customer_findings(ctx, R, A):
    """Customer-safe bullet points. No internal tooling, no platform-side configuration."""
    o, at, ta = R["oom"], R.get("atop"), A["traffic"]
    out = []

    def dom(name):
        return ctx.apps.get(name, {}).get("domain") or name
    if o["global"]:
        out.append("The server ran out of memory %d time(s)%s. Each time, the operating system stopped a running "
                   "service to recover, which interrupts the websites briefly."
                   % (o["global"], " (worst day: %s with %d events)" % o["peak_day"] if o["peak_day"] else ""))
    elif R["sys"]["checked"]:
        out.append("No out-of-memory events were recorded.")
    if R["reboots"]:
        out.append("The server restarted %d time(s): %s." % (len(R["reboots"]), ", ".join(r["ts"].strftime("%b %d %H:%M") for r in R["reboots"][:5])))
    elif R["sys"]["checked"]:
        out.append("The server did not restart during the period.")
    if at:
        out.append("Processor usage averaged %.0f%% and peaked at %.0f%%; memory usage averaged %.0f%% and peaked at %.0f%%."
                   % (at["cpu_avg"], at["cpu_peak"], at["mem_avg"], at["mem_peak"]))
    mc = sorted(((a, v["max_children"]) for a, v in R["fpm"]["per_app"].items() if v["max_children"]), key=lambda x: -x[1])
    if mc:
        out.append("The PHP worker limit was reached %d time(s) on %s, meaning requests had to wait for a free worker."
                   % (sum(c for _, c in mc), ", ".join(dom(a) for a, _ in mc[:3])))
    slow5 = sum(v["slow5"] for v in R["phpacc"]["per_app"].values())
    if slow5:
        out.append("%s PHP requests took longer than 5 seconds to complete (details below)." % fmt_num(slow5))
    sl = R["mysql_slow"]
    if sl["total"] >= 20:
        dbs = [dom(db) for db in list(sl["by_db"])[:2] if db != "(unknown)"]
        out.append("%s slow database queries were recorded%s." % (fmt_num(sl["total"]), ", mostly for " + ", ".join(dbs) if dbs else ""))
    restarts = len(R["mysql_err"]["startups"])
    if restarts:
        out.append("The database service restarted %d time(s) during the period." % restarts)
    if ta["req"]:
        out.append("Traffic: %s requests were served, %.1f%% of them with server errors (5xx). %s"
                   % (fmt_num(ta["req"]), ta["rate5"], ta["ddos"].replace(" (see signals)", "")))
    return out


class Report:
    """Plain-text report. With color=True it adds ANSI colours and box-drawing tables for terminals."""

    def __init__(self, color=False):
        self.out, self.color, self.n = [], color, 0
        self.box = color and "utf" in (getattr(sys.stdout, "encoding", "") or "").lower()

    def c(self, text, col):
        return "%s%s%s" % (ANSI[col], text, ANSI["reset"]) if self.color else text

    def hl(self, text):
        if not self.color:
            return text
        return HL_RE.sub(lambda m: self.c(m.group(0), HL_COLORS.get(m.group(0), "yellow")), text)

    def title(self, t):
        line = ("═" if self.box else "=") * WIDTH
        self.out += ["", self.c(line, "title"), self.c(t.center(WIDTH), "title"), self.c(line, "title")]

    def h2(self, t):
        self.n += 1
        line = self.c(("─" if self.box else "-") * WIDTH, "dim")
        self.out += ["", line, self.c("%d. %s" % (self.n, t), "h2"), line]

    def phase(self, t, sub):
        if self.color:
            bar = "bar2" if "PHASE 2" in t else "bar1"
            self.out += [""] + [self.c(x.ljust(WIDTH), bar) for x in ("", "  " + t, "  " + sub, "")]
        else:
            self.out += ["", "#" * WIDTH, ("  " + t).ljust(WIDTH), "  " + sub, "#" * WIDTH]

    def h3(self, t):
        self.out += ["", self.c("▸ " + t, "h3")]

    def kv(self, rows):
        rows = [(k, v) for k, v in rows if v not in (None, "")]
        w = max([len(k) for k, _ in rows] or [0])
        for k, v in rows:
            lines = textwrap.wrap(str(v), WIDTH - w - 6) or [""]
            self.out.append("  %s : %s" % (self.c(k.ljust(w), "key"), self.hl(lines[0])))
            self.out += ["  %s   %s" % (" " * w, self.hl(l)) for l in lines[1:]]

    def text(self, t, indent=2):
        lines = textwrap.wrap(t, WIDTH - indent, initial_indent=" " * indent, subsequent_indent=" " * (indent + 2)) or [""]
        if t.startswith((">>> ", "<<< ")):
            lines = [self.c(l, "green") for l in lines]
        self.out += [self.hl(l) for l in lines]

    def bullet(self, t, sev=None, level=0):
        tag = ""
        if sev:
            col = {"critical": "red", "warning": "yellow", "ok": "green", "info": "cyan"}[sev]
            tag = self.c("[%s] " % sev.upper(), col)
        pad = " " * (2 + 4 * level)
        lines = textwrap.wrap(t, WIDTH - len(pad) - 2 - (len(sev) + 3 if sev else 0)) or [""]
        self.out.append("%s%s %s%s" % (pad, "•" if self.box else "-", tag, self.hl(lines[0])))
        self.out += ["%s    %s" % (pad, self.hl(l)) for l in lines[1:]]

    def table(self, headers, rows, align=None, maxw=None):
        rows = [[str(x) for x in r] for r in rows]
        if not rows:
            self.out.append("  (no data)")
            return
        n = len(headers)
        align = align or (["l"] + ["r"] * (n - 1))
        if maxw:
            rows = [[trunc(x, maxw[i]) if maxw[i] else x for i, x in enumerate(r)] for r in rows]
        widths = [max([len(headers[i])] + [len(r[i]) for r in rows]) for i in range(n)]
        bar = self.c("│" if self.box else "|", "dim")

        def line(cells, head=False):
            parts = []
            for i, x in enumerate(cells):
                cell = x.rjust(widths[i]) if align[i] == "r" else x.ljust(widths[i])
                col = "th" if head else CELL_COLORS.get(x)
                parts.append(self.c(cell, col) if col else cell)
            return "  %s %s %s" % (bar, (" %s " % bar).join(parts), bar)

        def sep(chars):
            h = "─" if self.box else "-"
            left, mid, right = chars if self.box else "+++"
            return self.c("  " + left + mid.join(h * (w + 2) for w in widths) + right, "dim")
        self.out += [sep("┌┬┐"), line(headers, True), sep("├┼┤")] + [line(r) for r in rows] + [sep("└┴┘")]

    def blank(self):
        self.out.append("")

    def render(self):
        return "\n".join(self.out) + "\n"


HTML_CSS = """
:root{--ink:#1c2434;--mute:#64708a;--line:#e3e7ef;--bg:#f4f6fa;--card:#fff;--p1:#2f4aa8;--p2:#147a4b;
--red:#c62828;--amber:#b26a00;--green:#1b7f4a;--blue:#1f6fb5}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",
Inter,Roboto,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 22px 60px}
h1{font-size:26px;letter-spacing:.3px;margin:0 0 4px}
.sub{color:var(--mute);margin:0 0 22px}
.phase{color:#fff;border-radius:10px;padding:16px 20px;margin:34px 0 14px}
.phase.p1{background:linear-gradient(90deg,#2f4aa8,#4666d2)}
.phase.p2{background:linear-gradient(90deg,#147a4b,#22a567)}
.phase .pt{font-size:19px;font-weight:700;letter-spacing:.4px}
.phase .ps{opacity:.92;font-size:14px}
h2{font-size:18px;margin:26px 0 10px;padding:9px 14px;background:var(--card);border:1px solid var(--line);
border-left:5px solid var(--p1);border-radius:8px}
h2 .num{display:inline-block;min-width:28px;color:var(--p1);font-weight:800}
h3{font-size:15px;margin:20px 0 8px;color:#27314a;text-transform:uppercase;letter-spacing:.5px}
p{margin:6px 0}
.tw{overflow-x:auto;margin:8px 0 12px;border:1px solid var(--line);border-radius:8px;background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:13.5px;font-variant-numeric:tabular-nums}
table.data th{background:#eef1f8;text-align:left;font-weight:700;padding:8px 10px;border-bottom:2px solid var(--line);
white-space:nowrap}
table.data td{padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
table.data tr:nth-child(even) td{background:#fafbfd}
table.data .r{text-align:right;white-space:nowrap}
table.kv th{text-align:left;width:210px;color:var(--mute);font-weight:600;padding:7px 12px;vertical-align:top;
border-bottom:1px solid var(--line);white-space:nowrap}
table.kv td{padding:7px 12px;border-bottom:1px solid var(--line)}
.b{margin:5px 0 5px 4px;padding-left:16px;position:relative}
.b:before{content:"";position:absolute;left:2px;top:.62em;width:6px;height:6px;border-radius:50%;background:#9aa5bd}
.b.l1{margin-left:34px;color:#3c465e;font-size:14px}
.badge,.pill{display:inline-block;border-radius:20px;padding:1px 9px;font-size:11.5px;font-weight:700;
letter-spacing:.4px;margin-right:6px;color:#fff}
.critical,.k-red{background:var(--red)}.warning,.k-yellow{background:var(--amber)}
.ok,.k-green{background:var(--green)}.info{background:var(--blue)}.k-dim{background:#8b95ab}
.customer{background:var(--card);border:2px solid #22a567;border-radius:12px;padding:6px 22px 18px;margin:12px 0}
.customer .tag{display:inline-block;background:#22a567;color:#fff;font-weight:700;font-size:12px;letter-spacing:.5px;
border-radius:0 0 8px 8px;padding:3px 12px;margin-bottom:6px}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media print{body{background:#fff}.phase{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""


class HtmlReport(Report):
    """Same report as a self-contained HTML page (fonts, colours, real tables). No external resources."""

    def __init__(self, subtitle=""):
        Report.__init__(self, False)
        self.subtitle, self.doc_title = subtitle, "Server RCA"

    def hl(self, text):
        return HL_RE.sub(lambda m: '<span class="pill k-%s">%s</span>'
                         % (HL_COLORS.get(m.group(0), "yellow"), m.group(0).strip("[]")), html.escape(str(text), quote=False))

    def title(self, t):
        self.doc_title = t
        self.out.append("<h1>%s</h1>" % html.escape(t))
        if self.subtitle:
            self.out.append('<p class="sub">%s</p>' % html.escape(self.subtitle))

    def h2(self, t):
        self.n += 1
        self.out.append('<h2><span class="num">%d</span>%s</h2>' % (self.n, html.escape(t)))

    def phase(self, t, sub):
        self.out.append('<div class="phase %s"><div class="pt">%s</div><div class="ps">%s</div></div>'
                        % ("p2" if "PHASE 2" in t else "p1", html.escape(t), html.escape(sub)))

    def h3(self, t):
        self.out.append("<h3>%s</h3>" % html.escape(t))

    def kv(self, rows):
        rows = [(k, v) for k, v in rows if v not in (None, "")]
        self.out.append('<div class="tw"><table class="kv">%s</table></div>'
                        % "".join("<tr><th>%s</th><td>%s</td></tr>" % (html.escape(k), self.hl(v)) for k, v in rows))

    def text(self, t, indent=2):
        if t.startswith(">>> BEGIN CUSTOMER"):
            self.out.append('<div class="customer"><div class="tag">CUSTOMER RESPONSE - SAFE TO SHARE</div>')
        elif t.startswith("<<< END CUSTOMER"):
            self.out.append("</div>")
        else:
            self.out.append("<p>%s</p>" % self.hl(t))

    def bullet(self, t, sev=None, level=0):
        badge = '<span class="badge %s">%s</span>' % (sev, sev.upper()) if sev else ""
        self.out.append('<div class="b l%d">%s%s</div>' % (min(level, 1), badge, self.hl(t)))

    def table(self, headers, rows, align=None, maxw=None):
        if not rows:
            self.out.append("<p>(no data)</p>")
            return
        align = align or (["l"] + ["r"] * (len(headers) - 1))
        body = []
        for r in rows:
            cells = []
            for i, x in enumerate(r):
                x = str(x)
                inner = '<span class="pill k-%s">%s</span>' % (CELL_COLORS[x], x) if x in CELL_COLORS else html.escape(x, quote=False)
                cells.append('<td%s>%s</td>' % (' class="r"' if align[i] == "r" else "", inner))
            body.append("<tr>%s</tr>" % "".join(cells))
        head = "".join('<th%s>%s</th>' % (' class="r"' if align[i] == "r" else "", html.escape(h)) for i, h in enumerate(headers))
        self.out.append('<div class="tw"><table class="data"><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>'
                        % (head, "".join(body)))

    def blank(self):
        pass

    def render(self):
        return ('<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">'
                "<title>%s</title><style>%s</style></head>\n<body><div class=\"wrap\">\n%s\n</div></body></html>\n"
                % (html.escape(self.doc_title), HTML_CSS, "\n".join(self.out)))


def render_customer_slow(d, ctx, R, A):
    """Customer-safe list of slow PHP requests and slow database queries, matched against the incident hours."""
    inc = set(A["incident_hours"])
    pa, slow, sl = R["phpacc"]["per_app"], R["slow"], R["mysql_slow"]

    def dom(name):
        return ctx.apps.get(name, {}).get("domain") or name
    php = []
    for n in set(pa) | set(slow):
        v, t = pa.get(n), slow.get(n)
        if not ((v and v["slow5"]) or t):
            continue
        during = sum(c for hk, c in t["hours"].items() if hk in inc) if t else 0
        php.append((during, v["slow5"] if v else 0, t["traces"] if t else 0, n, v, t))
    php.sort(key=lambda x: (-x[0], -x[1], -x[2]))
    dbs = sorted(((sum(c for hk, c in v["hours"].items() if hk in inc), v["time"], db, v) for db, v in sl["by_db"].items()),
                 key=lambda x: (-x[0], -x[1]))
    if not php and not dbs:
        d.bullet("No slow PHP requests or slow database queries were recorded in the period.")
        return
    if inc:
        d.text("%d incident hour(s) were identified in the period (out-of-memory events, restarts, service failures "
               "or bursts of server errors). 'During incidents' counts the slow activity recorded inside those hours."
               % len(inc))
    else:
        d.text("No outage window was identified in the period, so the heaviest slow operations are listed for reference.")
    if php:
        d.h3("Slow PHP requests")
        d.table(["Website", "Requests >= 5s", "Requests >= 30s", "Slowest (s)", "Slow-log entries", "During incidents", "Main source"],
                [[dom(n), fmt_num(v["slow5"]) if v else "-", fmt_num(v["slow30"]) if v else "-",
                  "%.0f" % v["max_dur"] if v else "-", t["traces"] if t else 0, during if inc else "-",
                  t["components"][0][0] if t and t["components"] else "-"] for during, _, _, n, v, t in php[:5]],
                align=["l", "r", "r", "r", "r", "r", "l"], maxw=[34, 0, 0, 0, 0, 0, 30])
        for during, _, _, n, v, t in php[:3]:
            for fn, c in (t["functions"] if t else []):
                d.bullet("%s: %s - seen in %d slow request(s)" % (dom(n), fn, c))
            for u, hits, cpu, avg in (v.get("top_uris", [])[:3] if v else []):
                if avg >= 1:
                    d.bullet("%s: %s - %s request(s), %.1f s on average" % (dom(n), trunc(u, 60), fmt_num(hits), avg))
    if dbs:
        d.h3("Slow database queries")
        d.table(["Website / database", "Slow queries", "Total time (s)", "Longest (s)", "During incidents"],
                [[dom(db), fmt_num(v["count"]), "%.0f" % v["time"], "%.1f" % v["max"], during if inc else "-"]
                 for during, _, db, v in dbs[:5]], align=["l", "r", "r", "r", "r"], maxw=[40, 0, 0, 0, 0])
        d.text("Slowest queries (values masked):")
        d.table(["Website / database", "Count", "Total s", "Longest s", "Rows examined", "Query"],
                [[dom(a["db"]), a["count"], "%.0f" % a["time"], "%.1f" % a["max"], fmt_num(a["rows_ex"] // a["count"]), a["fp"]]
                 for a in sl["fingerprints"][:5]], align=["l", "r", "r", "r", "r", "l"], maxw=[26, 0, 0, 0, 0, 50])
    if inc:
        tr_all, tr_in = sum(x[2] for x in php), sum(x[0] for x in php)
        q_all, q_in = sl["total"], sum(x[0] for x in dbs)
        parts = []
        if q_all:
            parts.append("%s of %s slow database queries (%.0f%%)" % (fmt_num(q_in), fmt_num(q_all), pct(q_in, q_all)))
        if tr_all:
            parts.append("%s of %s slow PHP log entries (%.0f%%)" % (fmt_num(tr_in), fmt_num(tr_all), pct(tr_in, tr_all)))
        if parts:
            share = pct(q_in + tr_in, q_all + tr_all)
            d.text("%s were recorded during the incident hours. %s" % (
                " and ".join(parts),
                "This slow activity coincided with the outages and is the first thing to optimise." if share >= 30 else
                "Most of the slow activity happened outside the incident hours, so it is a general performance "
                "concern rather than the direct trigger of the outages."))


def render_top_apps(d, ctx, rows, customer=False):
    """Top applications by CPU and memory with traffic status. customer=True uses domains only."""
    if not rows:
        d.bullet("No application activity could be measured in the window.", "info")
        return

    def label(r):
        return (r["domain"] or r["app"]) if customer else r["app"]
    res = []
    for i, r in enumerate(rows, 1):
        row = [i, label(r)]
        if not customer:
            row += [trunc(r["domain"], 30), r["type"]]
        row += ["%.0f%%" % r["cpu_avg"], "%.0f%%" % r["cpu_peak"] if r["cpu_peak"] is not None else "-", "%.0f%%" % r["srv_pct"],
                fmt_kb(r["mem_avg_kb"]) if r["mem_avg_kb"] is not None else "-",
                fmt_kb(r["mem_peak_kb"]) if r["mem_peak_kb"] is not None else "-", "%.0f%%" % r["mem_pct"]]
        if not customer:
            row += [fmt_num(r["php_req"]) if r["php_req"] is not None else "-", "%.0f" % r["ms_req"] if r["ms_req"] is not None else "-"]
        res.append(row)
    heads = ["#", "Website" if customer else "Application"] + ([] if customer else ["Domain", "Type"]) + \
            ["CPU avg", "CPU peak", "Server CPU", "Mem avg", "Mem peak", "RAM share"] + ([] if customer else ["PHP req", "CPU ms/req"])
    d.table(heads, res, align=["r", "l"] + ([] if customer else ["l", "l"]) + ["r"] * (len(heads) - (2 if customer else 4)))
    d.text("CPU avg/peak are % of one CPU core; Server CPU is the share of the whole server."
           + ("" if customer else " Source: %s." % ", ".join(sorted({r["cpu_src"] for r in rows}))))
    tr = []
    for i, r in enumerate(rows, 1):
        t = r["traffic"]
        if t["status"] == "No data":
            tr.append([i, label(r), "-", "-", "-", "-", "-", "No data"])
        else:
            tr.append([i, label(r), fmt_num(t["req"]), fmt_num(int(round(t["per_hour"]))),
                       "%s (%s:00)" % (fmt_num(t["peak_hour_req"]), t["peak_hour"][5:]), "%.1f%%" % t["s5_pct"],
                       "%.0f%%" % t["bot_pct"], t["status"]])
    d.table(["#", "Website" if customer else "Application", "Requests", "Per hour", "Peak hour", "5xx", "Bots", "Traffic status"],
            tr, align=["r", "l", "r", "r", "r", "r", "r", "l"])
    floor = next((r["traffic"]["floor"] for r in rows if "floor" in r["traffic"]), None)
    if floor and not customer:
        d.text("Traffic status is judged against the server size: on this server a spike, a dominant client or a "
               "high bot share is only flagged from about %s requests/hour." % fmt_num(floor))
    for i, r in enumerate(rows, 1):
        d.bullet("%d. %s: %s" % (i, label(r), r["insight"]))
        for f in r["traffic"]["flags"]:
            d.bullet("Traffic: " + f, level=1)


def build_report(ctx, R, color=False, d=None):
    d = d or Report(color)
    meta, base, A, o = R["meta"], R["base"], R["analysis"], R["oom"]
    at, cfg, live, top = R.get("atop"), R["config"], R["live"], ctx.args.top
    start, end = meta["start"], meta["end"]
    days = [x.strftime("%Y-%m-%d") for x in day_list(start, end)]
    d.title("CLOUDWAYS SERVER RCA INVESTIGATION REPORT")

    # 1 ----------------------------------------------------------------------
    d.phase("PHASE 1 - FULL INSIGHTS (INTERNAL)",
            "Everything found, most useful first. Sharing is optional - never share the Imunify note.")

    d.h2("EXECUTIVE SUMMARY")
    fpm_hits = sum(v["max_children"] for v in R["fpm"]["per_app"].values())
    d.kv([
        ("Verdict", A["verdict"]),
        ("Root cause", "%s [%s]" % (A["root_cause"], A["confidence"])),
        ("Memory driver", A["driver"][1] if A["driver"] else None),
        ("Contributing", "; ".join(A["contributing"]) or None),
        ("Upscale", "%s%s - %s" % (A["upscale"][0].upper(), " to " + A["upscale"][1] if A["upscale"][1] else "", A["upscale"][2])),
        ("Server", "%s (%s) - %s GB RAM / %d vCPU / %d app(s)" % (base["hostname"], base["ips"][0] if base["ips"] else "?",
                                                                  base["ram_gb"], base["ncpu"], base["apps"])),
        ("Window", "%s -> %s %s" % (start.strftime("%Y-%m-%d %H:%M"), end.strftime("%Y-%m-%d %H:%M"), TZ_NAME)),
        ("Incidents", "%s OOM kill(s) | %d reboot(s) | %d service failure event(s) | %d FPM max_children hit(s) | %s slow queries"
         % (o["total"] if R["sys"]["checked"] else "?", len(R["reboots"]), len(R["sys"]["svc_events"]), fpm_hits,
            fmt_num(R["mysql_slow"]["total"]))),
        ("Resources", "CPU %.0f%% avg / %.0f%% peak | memory %.0f%% avg / %.0f%% peak | swap peak %s"
         % (at["cpu_avg"], at["cpu_peak"], at["mem_avg"], at["mem_peak"], fmt_kb(at["swap_peak_kb"])) if at else "no atop history"),
        ("Traffic", ("%s requests, %.2f%% 5xx. %s" % (fmt_num(A["traffic"]["req"]), A["traffic"]["rate5"], A["traffic"]["ddos"]))
         if A["traffic"]["req"] else A["traffic"]["ddos"]),
    ])
    if not ctx.is_root:
        d.bullet("Not run as root - kernel logs, MySQL and PHP-FPM master logs were unreadable. Treat this as partial.", "warning")
    main = [f for f in A["findings"] if f["sev"] in ("critical", "warning")]
    d.h3("Main findings")
    if main:
        for f in main[:8]:
            d.bullet(f["title"], f["sev"])
        if len(main) > 8:
            d.text("... %d more under KEY FINDINGS." % (len(main) - 8))
    else:
        d.bullet("Nothing abnormal detected in the window.", "ok")
    d.h3("What to do")
    for i, x in enumerate(A["optimizations"], 1):
        d.text("%d. %s" % (i, x))

    d.h2("TOP 3 APPLICATIONS BY CPU AND MEMORY (WITH TRAFFIC STATUS)")
    render_top_apps(d, ctx, A["top_apps"])

    d.h2("INVESTIGATION OVERVIEW")
    hours = (end - start).total_seconds() / 3600.0
    d.kv([
        ("Server", "%s (%s)" % (base["hostname"], base["ips"][0] if base["ips"] else "?")),
        ("Generated at", "%s %s" % (meta["now"].strftime("%Y-%m-%d %H:%M:%S"), TZ_NAME)),
        ("Investigation window", "%s -> %s %s (%s)" % (start.strftime("%Y-%m-%d %H:%M"), end.strftime("%Y-%m-%d %H:%M"), TZ_NAME,
                                                        "%.1f days" % (hours / 24) if hours >= 48 else "%.1f hours" % hours)),
        ("Window chosen via", meta["how"]),
        ("Privileges", "root" if ctx.is_root else "NON-ROOT (%s) - some logs are unreadable; results are partial" % uid_name(os.geteuid())),
        ("System log sources", "; ".join(R["sys"]["sources"]) or "none readable"),
        ("History source", "atop (%d x %ds intervals, %d daily file(s))" % (at["intervals"], at["interval_s"], at["files"]) if at else "not available"),
        ("Tool version", VERSION),
    ])
    d.text("Read-only investigation. All times are server local time (%s). 'Estimated' marks derived values; "
           "everything else is measured from logs." % TZ_NAME)
    if ctx.notes:
        d.h3("Data availability notes")
        for n in ctx.notes:
            d.bullet(n, "info")

    # 2 ----------------------------------------------------------------------
    d.h2("SERVER BASELINE AND CURRENT STATE")
    root_fs = next((f for f in base["filesystems"] if f["mount"] == "/"), None)
    d.kv([
        ("Plan (nominal)", "%s GB RAM / %d vCPU / %s" % (base["ram_gb"], base["ncpu"],
                                                         "%.0f GB disk (%.0f%% used, inodes %.0f%%)" % (root_fs["size_gb"], root_fs["used_pct"], root_fs["inode_pct"]) if root_fs else "disk n/a")),
        ("OS / kernel", "%s / %s" % (base["os"], base["kernel"])),
        ("Applications", "%d (%s)" % (base["apps"], ", ".join("%d %s" % (n, t) for t, n in base["app_types"]) or "none found")),
        ("Uptime", "booted %s (%s ago)" % (base["boot"].strftime("%Y-%m-%d %H:%M:%S"), str(meta["now"] - base["boot"]).split(".")[0]) if base["boot"] else "n/a"),
        ("Load average (now)", " ".join(base["load"]) or "n/a"),
        ("Memory used (now)", "%s / %s (%.0f%%)" % (fmt_kb(base["ram_used_kb"]), fmt_kb(base["ram_kb"]), base["ram_used_pct"]) if base["ram_kb"] else "n/a"),
        ("Swap used (now)", "%s / %s (swappiness %s)" % (fmt_kb(base["swap_used_kb"]), fmt_kb(base["swap_kb"]), base["swappiness"] or "?") if base["ram_kb"] else "n/a"),
    ])
    for fs in base["filesystems"]:
        if fs["mount"] != "/":
            d.kv([("Disk " + fs["mount"], "%.0f%% of %.0f GB, inodes %.0f%%" % (fs["used_pct"], fs["size_gb"], fs["inode_pct"]))])
    if live["groups"]:
        d.h3("Memory by consumer (right now)")
        d.table(["Consumer", "Procs", "RSS", "RAM%", "Role"],
                [[owner_label(ctx, k[0], k[1]), g["n"], fmt_kb(g["rss_kb"]), "%.0f%%" % pct(g["rss_kb"], base["ram_kb"]), role_of(*k)]
                 for k, g in live["groups"][:max(top, 10)]], align=["l", "r", "r", "r", "l"], maxw=[44, 0, 0, 0, 44])
        d.h3("Largest processes (right now)")
        d.table(["PID", "Process", "Owner", "RSS", "Command"],
                [[p["pid"], p["comm"], uid_name(p["uid"]), fmt_kb(p["rss_kb"]), p["cmd"] or p["comm"]] for p in live["procs"][:10]],
                align=["r", "l", "l", "r", "l"], maxw=[0, 18, 16, 0, 44])
    if R["services"]:
        d.h3("Services (current status)")
        d.table(["Service", "State", "Active since", "Restarted in window", "systemd restarts", "Memory"],
                [[s["unit"], "%s/%s" % (s["active"], s["sub"]), s["since"].strftime("%Y-%m-%d %H:%M:%S") if s["since"] else "-",
                  "YES" if s["since"] and start <= s["since"] <= end else "no",
                  s["nrestarts"] if s["nrestarts"] is not None else "-", fmt_kb(s["mem_kb"]) if s["mem_kb"] else "-"]
                 for s in R["services"]], align=["l", "l", "l", "l", "r", "r"])

    # 3 ----------------------------------------------------------------------
    d.h2("INCIDENT TIMELINE")
    fpm_day = Counter()
    for v in R["fpm"]["per_app"].values():
        fpm_day.update(v["by_day"])
    req_day, e5_day = Counter(), Counter()
    for hk, n in R["traffic"]["hour_req"].items():
        req_day[hk[:10]] += n
    for hk, n in R["traffic"]["hour_5xx"].items():
        e5_day[hk[:10]] += n
    rb_day = Counter(r["ts"].strftime("%Y-%m-%d") for r in R["reboots"])
    sv_day = Counter(e["ts"].strftime("%Y-%m-%d") for e in R["sys"]["svc_events"])
    st_day = Counter()
    for (svc, day), n in R["sys"]["svc_starts"].items():
        st_day[day] += n
    rows = []
    for day in days:
        ad = at["days"].get(day) if at else None
        rows.append([day, o["by_day"].get(day, 0), rb_day.get(day, 0), sv_day.get(day, 0), st_day.get(day, 0),
                     fpm_day.get(day, 0), R["mysql_slow"]["by_day"].get(day, 0), fmt_num(req_day.get(day, 0)),
                     fmt_num(e5_day.get(day, 0)),
                     "%.0f/%.0f%%" % (ad["cpu_avg"], ad["cpu_peak"]) if ad else "-",
                     "%.0f/%.0f%%" % (ad["mem_avg"], ad["mem_peak"]) if ad else "-"])
    d.table(["Date", "OOM", "Reboots", "Svc fail", "Svc starts", "FPM max", "Slow SQL", "Requests", "5xx",
             "CPU avg/pk", "Mem avg/pk"], rows)
    d.text("OOM = kernel OOM kills; Svc fail = systemd failure/auto-restart events; Svc starts = starts of web/DB/cache "
           "services; FPM max = pm.max_children reached; CPU/Mem from atop.")
    worst = (o["peak_day"][0] if o["peak_day"] else None) or (e5_day.most_common(1)[0][0] if e5_day else None) or \
            (max(at["days"], key=lambda k: at["days"][k]["cpu_avg"]) if at else None)
    worst_ad = at["days"].get(worst) if (at and worst) else None
    if worst and (o["by_day"].get(worst) or e5_day.get(worst, 0) >= 20 or (worst_ad and worst_ad["cpu_avg"] >= 60)):
        hrs = []
        for h in range(24):
            hk = "%s %02d" % (worst, h)
            row = [o["by_hour"].get(hk, 0), R["traffic"]["hour_req"].get(hk, 0), R["traffic"]["hour_5xx"].get(hk, 0),
                   R["fpm"]["by_hour"].get(hk, 0), R["mysql_slow"]["by_hour"].get(hk, 0),
                   round(R["phpacc"]["hour_cpu"].get(hk, 0))]
            if any(row):
                hrs.append(["%02d:00" % h] + [fmt_num(x) for x in row])
        if hrs:
            d.h3("Hourly breakdown of the worst day (%s)" % worst)
            d.table(["Hour", "OOM", "Requests", "5xx", "FPM max", "Slow SQL", "PHP CPU s"], hrs)

    # 4 ----------------------------------------------------------------------
    d.h2("OOM (OUT-OF-MEMORY) ANALYSIS")
    if not R["sys"]["checked"]:
        d.bullet("Kernel logs could not be read - OOM kills were NOT checked. Run as root.", "warning")
    elif not o["total"]:
        d.bullet("No OOM-killer events in the window.", "ok")
    else:
        d.kv([("Total OOM kills", "%d (%d server-wide, %d cgroup-limited)" % (o["total"], o["global"], o["cgroup"])),
              ("Peak day", "%s (%d kills)" % o["peak_day"]),
              ("Peak hour", "%s:00 (%d kills)" % o["by_hour"].most_common(1)[0]),
              ("Hour-of-day pattern", "  ".join("%02dh:%d" % (h, n) for h, n in sorted(o["hod"].items()))),
              ("Swap at kill time", "exhausted (<2%% free) in %d of %d kernel reports" % (o["swap_exhausted"], o["swap_known"]) if o["swap_known"] else "not reported"),
              ("OOM triggered by", ", ".join("%s (%d)" % kv for kv in o["triggers"]) or "n/a")])
        d.h3("Victims (processes killed)")
        rss = defaultdict(list)
        for e in R["sys"]["oom"]:
            if e["anon_rss_kb"]:
                rss[e["name"]].append(e["anon_rss_kb"])
        d.table(["Process", "OOM kills", "Share", "Avg RSS at kill", "Role"],
                [[n, c, "%.0f%%" % pct(c, o["total"]), fmt_kb(sum(rss[n]) / len(rss[n])) if rss[n] else "-",
                  role_of(*classify(ctx, n))] for n, c in o["by_proc"][:10]], align=["l", "r", "r", "r", "l"])
        appk = Counter(e["owner"] for e in R["sys"]["oom"] if e["kind"] == "app")
        if appk:
            d.text("PHP workers killed per application: " + ", ".join("%s (%d)" % kv for kv in appk.most_common(8)))
        if o["holders"]:
            d.h3("Who held the memory when the kernel killed (average of %d kernel task dumps)" % o["dumps"])
            d.table(["Memory holder", "Avg RSS", "Share", "Peak RSS", "Role"],
                    [[owner_label(ctx, h["kind"], h["owner"]), fmt_kb(h["avg_kb"]), "%.0f%%" % h["share"], fmt_kb(h["peak_kb"]),
                      role_of(h["kind"], h["owner"])] for h in o["holders"][:10]], align=["l", "r", "r", "r", "l"], maxw=[44, 0, 0, 0, 0])
            d.text("The victim is whichever process the kernel scores highest (usually the largest), not necessarily "
                   "the cause. This table shows what actually filled the RAM.")
        d.h3("OOM kills per day")
        d.table(["Date", "Kills", "Top victim", "Busiest hour"],
                [[day, n, Counter(e["name"] for e in R["sys"]["oom"] if e["ts"].strftime("%Y-%m-%d") == day).most_common(1)[0][0],
                  "%s:00 (%d)" % max(((hk[11:], c) for hk, c in o["by_hour"].items() if hk.startswith(day)), key=lambda x: x[1])]
                 for day, n in sorted(o["by_day"].items())], align=["l", "r", "l", "l"])

    # 5 ----------------------------------------------------------------------
    d.h2("REBOOTS AND SERVICE STABILITY")
    if R["reboots"]:
        d.table(["Boot time", "Shutdown record"],
                [[r["ts"].strftime("%Y-%m-%d %H:%M:%S"),
                  {True: "clean shutdown recorded", False: "NONE - crash, hard reset or provider-level event", None: "unknown"}[r["clean"]]]
                 for r in R["reboots"]], align=["l", "l"])
    else:
        d.bullet("No reboots in the window.", "ok")
    starts = Counter()
    for (svc, day), n in R["sys"]["svc_starts"].items():
        starts[svc] += n
    if starts:
        d.h3("Service (re)starts in the window")
        d.table(["Service", "Starts", "Busiest day"],
                [[svc, n, "%s (%d)" % max(((dy, c) for (s2, dy), c in R["sys"]["svc_starts"].items() if s2 == svc), key=lambda x: x[1])]
                 for svc, n in starts.most_common()], align=["l", "r", "l"])
        d.text("Starts include platform-driven reloads (settings changes, deployments); compare with the failure events below.")
    if R["sys"]["svc_events"]:
        d.h3("Service failure / auto-restart events (systemd)")
        ev = R["sys"]["svc_events"]
        d.table(["Time", "Service", "Event"], [[e["ts"].strftime("%Y-%m-%d %H:%M:%S"), e["unit"], e["what"]] for e in ev[:25]],
                align=["l", "l", "l"], maxw=[0, 0, 60])
        if len(ev) > 25:
            d.text("... %d more event(s) not shown." % (len(ev) - 25))
    elif R["sys"]["checked"]:
        d.bullet("No service failures logged by systemd in the window.", "ok")

    # 6 ----------------------------------------------------------------------
    d.h2("RESOURCE HISTORY (ATOP)")
    if not at:
        d.bullet("atop history is not available for this window (see notes).", "info")
    else:
        d.kv([("CPU busy", "%.0f%% avg / %.0f%% peak; %d of %d intervals >= 85%%" % (at["cpu_avg"], at["cpu_peak"], at["cpu_high"], at["intervals"])),
              ("Memory used", "%.0f%% avg / %.0f%% peak; %d intervals >= 90%%" % (at["mem_avg"], at["mem_peak"], at["mem_high"])),
              ("Swap used (peak)", "%s of %s" % (fmt_kb(at["swap_peak_kb"]), fmt_kb(base["swap_kb"]))),
              ("I/O wait / steal", "%.1f%% / %.1f%% avg" % (at["iowait"], at["steal"]))])
        d.h3("Per day")
        d.table(["Date", "CPU avg", "CPU peak", ">=85% intervals", "Mem avg", "Mem peak", "Swap peak", "Load peak", "IO wait", "Steal"],
                [[day, "%.0f%%" % v["cpu_avg"], "%.0f%%" % v["cpu_peak"], "%d/%d" % (v["cpu_high"], v["n"]), "%.0f%%" % v["mem_avg"],
                  "%.0f%%" % v["mem_peak"], fmt_kb(v["swap_peak_kb"]), "%.1f" % v["load_peak"], "%.1f%%" % v["iowait"], "%.1f%%" % v["steal"]]
                 for day, v in sorted(at["days"].items())])
        d.h3("Top CPU consumers over the window (% of one vCPU core)")
        oc = sorted(at["owners"], key=lambda x: -x["cpu_avg"])[:top]
        d.table(["Consumer", "CPU avg", "Srv%", "CPU peak", "Peak at", "RSS avg", "RSS peak"],
                [[owner_label(ctx, x["kind"], x["owner"]), "%.0f%%" % x["cpu_avg"], "%.0f%%" % (x["cpu_avg"] / base["ncpu"]),
                  "%.0f%%" % x["cpu_peak"], x["cpu_peak_at"], fmt_kb(x["rss_avg_kb"]), fmt_kb(x["rss_peak_kb"])] for x in oc],
                maxw=[44, 0, 0, 0, 0, 0, 0])
        d.h3("Top memory consumers over the window (RSS of active processes)")
        om = sorted(at["owners"], key=lambda x: -x["rss_peak_kb"])[:top]
        d.table(["Consumer", "RSS avg", "RSS peak", "Peak RAM%", "Peak at"],
                [[owner_label(ctx, x["kind"], x["owner"]), fmt_kb(x["rss_avg_kb"]), fmt_kb(x["rss_peak_kb"]),
                  "%.0f%%" % pct(x["rss_peak_kb"], base["ram_kb"]), x["rss_peak_at"]] for x in om], maxw=[44, 0, 0, 0, 0])

        def tops(lst, unit):
            return ", ".join("%s %s" % (owner_label(ctx, k[0], k[1]).split(" (")[0],
                                         ("%.0f%%" % v) if unit == "cpu" else fmt_kb(v)) for k, v in lst) or "-"
        d.h3("Worst CPU intervals")
        d.table(["Time", "CPU busy", "Top consumers (% of one core)"], [[t, "%.0f%%" % c, tops(l, "cpu")] for c, t, l in at["worst_cpu"]],
                align=["l", "r", "l"], maxw=[0, 0, 70])
        d.h3("Worst memory intervals")
        d.table(["Time", "Mem used", "Swap used", "Top holders (RSS)"], [[t, "%.0f%%" % m, fmt_kb(sw), tops(l, "mem")] for m, t, l, sw in at["worst_mem"]],
                align=["l", "r", "r", "l"], maxw=[0, 0, 0, 62])
        d.text("atop records only processes that were active in an interval, so RSS totals are a lower bound.")

    # 7 ----------------------------------------------------------------------
    d.h2("CONFIGURATION REVIEW (RED FLAGS)")
    fp, ap, rd = cfg["fpm"], cfg["apache"], cfg["redis"]
    d.kv([
        ("Apache", "mpm %s; %s" % (ap["mpm"], ", ".join("%s=%s" % kv for kv in sorted(ap["values"].items())) or "limits not found")),
        ("PHP-FPM", "%d pools, %d workers allowed in total; memory_limit up to %s; live worker avg %s"
         % (fp["pools"], fp["total_children"], "%.0f MB" % fp["max_memory_limit_mb"] if fp["max_memory_limit_mb"] else "?",
            "%.0f MB" % fp["worker_avg_mb"] if fp["worker_avg_mb"] else "n/a")),
        ("MariaDB/MySQL", "innodb_buffer_pool_size %s; max_connections %s"
         % (fmt_kb(cfg["innodb_buffer_pool_mb"] * 1024) if cfg["innodb_buffer_pool_mb"] else "?", cfg["max_connections"] or "?")),
        ("Redis", ("used %s, maxmemory %s, policy %s" % (fmt_kb(rd["used_mb"] * 1024) if "used_mb" in rd else "?",
                                                         fmt_kb(rd["maxmemory_mb"] * 1024) if rd.get("maxmemory_mb") else "UNLIMITED (0)",
                                                         rd.get("policy") or "?")) if rd else "not detected"),
        ("Elasticsearch heap", fmt_kb(cfg["es_heap_mb"] * 1024) if cfg.get("es_heap_mb") else None),
        ("Varnish", fmt_kb(cfg["varnish_mb"] * 1024) if cfg.get("varnish_mb") else None),
    ])
    if cfg["budget"]:
        d.h3("Memory budget (configured ceilings vs RAM)")
        d.table(["Component", "Ceiling", "% of RAM"],
                [[k, fmt_kb(v * 1024), "%.0f%%" % pct(v * 1024, base["ram_kb"])] for k, v in cfg["budget"]] +
                [["TOTAL (worst case)", fmt_kb(cfg["budget_total_mb"] * 1024), "%.0f%%" % pct(cfg["budget_total_mb"] * 1024, base["ram_kb"])],
                 ["Server RAM", fmt_kb(base["ram_kb"]), "100%"]])
        d.text("Worst case is theoretical (every pool at max_children at once), but a ratio far above 100% means "
               "nothing stops PHP from exhausting RAM during a spike. (PHP-FPM figure is estimated.)")
    if cfg["flags"]:
        for sev, text in cfg["flags"]:
            d.bullet(text, sev)
    else:
        d.bullet("No configuration red flags detected.", "ok")

    # 8 ----------------------------------------------------------------------
    d.h2("PHP-FPM INVESTIGATION")
    pa, fpm, slow = R["phpacc"]["per_app"], R["fpm"]["per_app"], R["slow"]
    names = sorted(set(pa) | set(fpm) | set(slow), key=lambda n: -(pa.get(n, {}).get("cpu_s", 0) + fpm.get(n, {}).get("max_children", 0)))
    if not names:
        d.bullet("No PHP-FPM activity found in the window (or logs unreadable).", "info")
    else:
        tot_cpu = sum(v["cpu_s"] for v in pa.values()) or 1
        rows = []
        for n in names[:top]:
            v, f, s = pa.get(n), fpm.get(n, {}), slow.get(n, {})
            pool = next((p for p in ctx.pools.values() if p.get("app") == n), {})
            rows.append([n, trunc(ctx.apps.get(n, {}).get("domain", ""), 28), fmt_num(v["req"]) if v else "-",
                         fmt_num(round(v["cpu_s"])) if v else "-", "%.0f%%" % pct(v["cpu_s"], tot_cpu) if v else "-",
                         "%.0f" % (v["cpu_s"] / v["req"] * 1000) if v else "-", "%.2f" % (v["dur"] / v["req"]) if v else "-",
                         "%d/%d" % (v["slow5"], v["slow30"]) if v else "-", "%.0f/%.0f" % (v["mem_sum"] / v["req"], v["mem_max"]) if v else "-",
                         f.get("max_children", 0), pool.get("pm.max_children", "?"), s.get("traces", 0)])
        d.table(["Application", "Domain", "PHP req", "CPU s", "CPU share", "ms/req", "Avg s", ">=5s/>=30s", "MB avg/max",
                 "max_ch hits", "Limit", "Slow traces"], rows, align=["l", "l"] + ["r"] * 10)
        d.text("CPU s = PHP CPU-seconds measured in the FPM access log; CPU share = share of all PHP CPU on the server; "
               "max_ch hits = times pm.max_children was reached.")
        for n in names[:min(top, 5)]:
            v, s, f = pa.get(n), slow.get(n), fpm.get(n, {})
            if not ((v and v.get("top_uris")) or s):
                continue
            d.h3("%s (%s)" % (n, ctx.apps.get(n, {}).get("domain") or "no domain"))
            if f.get("sigkill") or f.get("sigsegv") or f.get("timeouts"):
                d.text("Workers killed (SIGKILL) %d, crashed (SIGSEGV) %d, terminated on timeout %d."
                       % (f.get("sigkill", 0), f.get("sigsegv", 0), f.get("timeouts", 0)))
            if v and v.get("top_uris"):
                d.table(["Path (by CPU)", "Hits", "CPU s", "Avg s"],
                        [[u, hits, "%.1f" % cpu, "%.2f" % avg] for u, hits, cpu, avg in v["top_uris"]], maxw=[60, 0, 0, 0])
            if s:
                d.text("Slow-log traces: %d. Components: %s" % (s["traces"], ", ".join("%s (%d)" % kv for kv in s["components"]) or "-"))
                for fn, c in s["functions"]:
                    d.bullet("%s - %d trace(s)" % (fn, c), level=1)
    rs = R["fpm"]["restarts"]
    if rs:
        d.text("PHP-FPM master (re)starts per day: " + ", ".join("%s: %d" % kv for kv in sorted(rs.items())))

    # 9 ----------------------------------------------------------------------
    d.h2("MYSQL / MARIADB INVESTIGATION")
    my, sl, el = R["mysql"], R["mysql_slow"], R["mysql_err"]
    st, vr = my.get("status", {}), my.get("vars", {})
    up = int(st["Uptime"]) if st.get("Uptime", "").isdigit() else None
    d.kv([
        ("Version", my.get("version") or ("unavailable: " + my.get("error", "?"))),
        ("Uptime", ("%s (started %s)%s" % (str(timedelta(seconds=up)), (meta["now"] - timedelta(seconds=up)).strftime("%Y-%m-%d %H:%M"),
                                           " - RESTARTED INSIDE THE WINDOW" if meta["now"] - timedelta(seconds=up) >= start else "")) if up is not None else None),
        ("Connections", "%s now, max used %s / %s; refused (max_connections) %s"
         % (st.get("Threads_connected", "?"), st.get("Max_used_connections", "?"), vr.get("max_connections", "?"),
            st.get("Connection_errors_max_connections", "?")) if st else None),
        ("Buffer pool", "%s configured, %s in use" % (fmt_kb(to_mb(vr.get("innodb_buffer_pool_size")) * 1024) if to_mb(vr.get("innodb_buffer_pool_size")) else "?",
                                                      fmt_kb(int(st["Innodb_buffer_pool_bytes_data"]) / 1024) if st.get("Innodb_buffer_pool_bytes_data", "").isdigit() else "?") if st else None),
        ("Slow log", "%s (enabled=%s, long_query_time=%ss)" % (sl["file"] or "not found", sl["enabled"], sl["long_query_time"])),
        ("Slow queries (window)", "%s (%d backup/dump)" % (fmt_num(sl["total"]), sl["dumps"])),
        ("Restarts in window", "%d startup(s), %d crash recover%s%s" % (len(el["startups"]), el["crash_recovery"], "y" if el["crash_recovery"] == 1 else "ies",
                                                                         ": " + ", ".join(t.strftime("%m-%d %H:%M") for t in el["startups"][:10]) if el["startups"] else "") if el["files"] else "error log not readable"),
        ("Error log", "'Too many connections' %d, out-of-memory %d, aborted connections %d, crashed tables %d"
         % (el["too_many_conn"], el["oom"], el["aborted"], sum(el["crashed_tables"].values())) if el["files"] else None),
    ])
    if my.get("db_sizes"):
        d.text("Largest databases: " + ", ".join("%s %s" % (n, fmt_kb(mb * 1024)) for n, mb in my["db_sizes"][:6]))
    if sl["by_db"]:
        d.h3("Slow queries per database")
        d.table(["Database", "Application", "Slow q", "Total s", "Max s"],
                [[db, ctx.apps.get(db, {}).get("domain") or ("-" if db not in ctx.apps else db), v["count"], "%.0f" % v["time"], "%.1f" % v["max"]]
                 for db, v in list(sl["by_db"].items())[:top]], align=["l", "l", "r", "r", "r"], maxw=[24, 34, 0, 0, 0])
        d.h3("Top slow-query fingerprints (literals masked)")
        d.table(["DB", "Count", "Total s", "Max s", "Rows exam.", "Query fingerprint"],
                [[a["db"], a["count"], "%.0f" % a["time"], "%.1f" % a["max"], fmt_num(a["rows_ex"] // a["count"]), a["fp"]]
                 for a in sl["fingerprints"][:8]], align=["l", "r", "r", "r", "r", "l"], maxw=[16, 0, 0, 0, 0, 52])
    if el["errors"]:
        d.h3("Most frequent MySQL error-log messages")
        for msg, c in el["errors"].most_common(5):
            d.bullet("%dx %s" % (c, msg))

    # 10 ---------------------------------------------------------------------
    d.h2("TRAFFIC ANALYSIS")
    ta, tr = A["traffic"], R["traffic"]
    if not ta["req"]:
        d.bullet("No web access log data for the window (logs missing, unreadable or --skip-traffic).", "info")
    else:
        d.kv([("Total requests", "%s across %d application(s)" % (fmt_num(ta["req"]), len(tr["per_app"]))),
              ("Volume", ta["volume"]),
              ("5xx responses", "%s (%.2f%%)" % (fmt_num(ta["s5"]), ta["rate5"])),
              ("Bot / tool share", "%.0f%%" % ta["bot_share"]),
              ("Busiest hour", "%s:00 with %s requests (median hour %s)" % (ta["peak_hour"][0], fmt_num(ta["peak_hour"][1]), fmt_num(ta["median_hour"]))),
              ("DDoS assessment", ta["ddos"])])
        own = set(base["ips"]) | {"127.0.0.1", "::1"}
        rows = []
        for n, a in sorted(tr["per_app"].items(), key=lambda kv: -kv[1]["req"])[:top]:
            ip, c = a["top_ips"][0]
            rows.append([n, trunc(ctx.apps.get(n, {}).get("domain", ""), 26), fmt_num(a["req"]) + ("*" if a["partial"] else ""),
                         fmt_num(a["unique_ips"]), fmt_num(a["s5"]), "%.1f%%" % pct(a["s5"], a["req"]), "%.0f%%" % pct(a["bots"], a["req"]),
                         fmt_num(a["login"]), fmt_num(a["xmlrpc"]), "%s (%s)" % (a["peak_hour"][5:] + "h", fmt_num(a["peak_hour_req"])),
                         "%s%s %.0f%%" % (ip, " (self)" if ip in own else "", pct(c, a["req"]))])
        d.table(["Application", "Domain", "Requests", "IPs", "5xx", "5xx%", "Bots", "wp-login", "xmlrpc", "Peak hour", "Top IP"],
                rows, align=["l", "l"] + ["r"] * 7 + ["l", "l"])
        d.text("'(self)' = the server's own IP (WP-Cron / loopback). '*' = log only partly parsed (time budget).")
        if tr["hour_5xx"]:
            d.h3("Worst hours for 5xx errors")
            d.table(["Hour", "5xx", "Requests", "5xx%", "OOM kills in hour"],
                    [[hk + ":00", fmt_num(c), fmt_num(tr["hour_req"].get(hk, 0)), "%.0f%%" % pct(c, tr["hour_req"].get(hk, 0)),
                      o["by_hour"].get(hk, 0)] for hk, c in tr["hour_5xx"].most_common(6)])
        if ta["signals"]:
            d.h3("Traffic signals")
            for s in ta["signals"]:
                d.bullet(s, "warning")
        else:
            d.bullet("No suspicious-traffic indicators triggered.", "ok")

    # 11 ---------------------------------------------------------------------
    d.h2("EVIDENCE AND SUPPORTING LOGS")
    ev = R["sys"]["oom"]
    if ev:
        d.h3("OOM kill events (%d%s)" % (len(ev), ", first 20 and last 10 shown" if len(ev) > 30 else ""))
        shown = ev if len(ev) <= 30 else ev[:20] + ev[-10:]
        d.table(["Time", "Victim", "PID", "RSS", "Scope", "Triggered by", "Top memory holders at that moment"],
                [[e["ts"].strftime("%Y-%m-%d %H:%M:%S"), e["name"], e["pid"], fmt_kb(e["anon_rss_kb"]) if e["anon_rss_kb"] else "-",
                  "cgroup" if e["cgroup"] else "server", e["trigger"] or "-",
                  ", ".join("%s %s" % (owner, fmt_kb(kb)) for _, owner, kb in e["holders"][:3]) or "-"] for e in shown],
                align=["l", "l", "r", "r", "l", "l", "l"], maxw=[0, 16, 0, 0, 0, 14, 44])
        d.h3("Raw kernel lines (first 3)")
        for e in ev[:3]:
            d.bullet(e["raw"])
    else:
        d.bullet("No OOM events to list.", "ok" if R["sys"]["checked"] else "info")

    # 12 ---------------------------------------------------------------------
    d.h2("KEY FINDINGS")
    if not A["findings"]:
        d.bullet("No findings: nothing abnormal was detected in the window.", "ok")
    for f in A["findings"]:
        d.bullet(f["title"], f["sev"])
        for e in f["evidence"]:
            d.bullet(e, level=1)
        if f["action"]:
            d.bullet("Next action: " + f["action"], level=1)

    # 13 ---------------------------------------------------------------------
    d.h2("ROOT CAUSE ANALYSIS")
    d.kv([("Root cause", A["root_cause"]), ("Confidence", A["confidence"]),
          ("Memory driver", A["driver"][1] if A["driver"] else None),
          ("Contributing", "; ".join(A["contributing"]) or "-")])
    d.h3("Top 5 culprits")
    if o["total"]:
        d.table(["Rank", "Process", "OOM kills", "Share", "Role"],
                [[i, n, c, "%.0f%%" % pct(c, o["total"]), role_of(*classify(ctx, n))] for i, (n, c) in enumerate(o["by_proc"][:5], 1)],
                align=["r", "l", "r", "r", "l"])
        d.text("Total OOM kills (window): %d | Peak day: %s (%d) | Reboots: %d"
               % (o["total"], o["peak_day"][0], o["peak_day"][1], len(R["reboots"])))
    elif at:
        oc = sorted(at["owners"], key=lambda x: -(x["cpu_avg"] / (base["ncpu"] * 100.0) + x["rss_peak_kb"] / (base["ram_kb"] or 1)))[:5]
        d.table(["Rank", "Consumer", "CPU avg", "CPU peak", "RSS peak", "Role"],
                [[i, owner_label(ctx, x["kind"], x["owner"]), "%.0f%%" % x["cpu_avg"], "%.0f%%" % x["cpu_peak"], fmt_kb(x["rss_peak_kb"]),
                  role_of(x["kind"], x["owner"])] for i, x in enumerate(oc, 1)], align=["r", "l", "r", "r", "r", "l"], maxw=[0, 44, 0, 0, 0, 0])
        d.text("No OOM kills - ranked by resource usage over the window. Reboots: %d" % len(R["reboots"]))
    else:
        d.text("No OOM kills and no atop history - culprits cannot be ranked. Reboots: %d" % len(R["reboots"]))
    d.h3("Other findings (brief)")
    d.table(["Area", "Finding"], brief_findings(ctx, R), align=["l", "l"], maxw=[24, 70])
    d.h3("Optimizations needed")
    for i, x in enumerate(A["optimizations"], 1):
        d.text("%d. %s" % (i, x))
    d.h3("Upscale?")
    up_ = A["upscale"]
    d.text("%s%s. %s" % (up_[0].upper(), " - " + up_[1] if up_[1] else "", up_[2]))
    d.h3("Verdict")
    d.text(A["verdict"])

    # 14 ---------------------------------------------------------------------
    if A["imunify"]["relevant"]:
        d.h2("INTERNAL NOTE - IMUNIFY (DO NOT SHARE WITH CUSTOMER)")
        for e in A["imunify"]["evidence"]:
            d.bullet(e)
        d.bullet("Suggested tuning: schedule malware scans off-peak, lower scan intensity (CPU/IO/RAM limits), and "
                 "review resident agents (WAF daemon, DoS detector) against the server size.")

    # 15 ---------------------------------------------------------------------
    d.phase("PHASE 2 - CUSTOMER-SHAREABLE REPORT",
            "Safe to send as-is: no internal tooling, no platform-side configuration.")
    d.h2("CUSTOMER-SHAREABLE REPORT")
    d.text(">>> BEGIN CUSTOMER RESPONSE >>>")
    d.h3("Summary")
    d.text(A["customer_short"])
    d.h3("What we found")
    for x in customer_findings(ctx, R, A):
        d.bullet(x)
    d.h3("Top applications by CPU and memory usage (with traffic status)")
    render_top_apps(d, ctx, A["top_apps"], customer=True)
    d.h3("Slow PHP requests and database queries (supporting evidence)")
    render_customer_slow(d, ctx, R, A)
    recs = [x for x in A["optimizations"] if not x.startswith("[INTERNAL]") and not x.startswith("No change")]
    d.h3("Recommendations")
    for k, x in enumerate(recs, 1):
        d.text("%d. %s" % (k, x))
    up2 = A["upscale"]
    if up2[0] == "Yes":
        d.text("%d. Upgrade the server to %s so it has enough capacity for the current workload." % (len(recs) + 1, up2[1]))
    elif up2[0] == "Optional":
        d.text("%d. If the issue recurs after the changes above, upgrade the server to %s." % (len(recs) + 1, up2[1]))
    elif not recs and A["root_cause"].startswith("Inconclusive"):
        d.text("Recommendations will follow once the full analysis is complete.")
    elif not recs:
        d.text("No action is required at this time; we will continue to monitor the server.")
    d.blank()
    d.text("<<< END CUSTOMER RESPONSE <<<")
    d.blank()
    return d


def brief_findings(ctx, R):
    base, at, cfg, A, o = R["base"], R.get("atop"), R["config"], R["analysis"], R["oom"]
    sl, el, ta = R["mysql_slow"], R["mysql_err"], A["traffic"]
    root_fs = next((f for f in base["filesystems"] if f["mount"] == "/"), None)
    starts = Counter()
    for (svc, _), n in R["sys"]["svc_starts"].items():
        starts[svc] += n
    return [
        ["CPU", "avg %.0f%% / peak %.0f%%, %d/%d intervals >= 85%%, steal %.1f%%" % (at["cpu_avg"], at["cpu_peak"], at["cpu_high"], at["intervals"], at["steal"]) if at else "no history (atop unavailable)"],
        ["RAM/Swap", ("avg %.0f%% / peak %.0f%% used; swap peak %s of %s" % (at["mem_avg"], at["mem_peak"], fmt_kb(at["swap_peak_kb"]), fmt_kb(base["swap_kb"]))) if at
         else "now %.0f%% used; swap %s of %s" % (base["ram_used_pct"], fmt_kb(base["swap_used_kb"]), fmt_kb(base["swap_kb"]))],
        ["Disk I/O", ("iowait avg %.1f%%; " % at["iowait"] if at else "") + ("/ %.0f%% full, inodes %.0f%%" % (root_fs["used_pct"], root_fs["inode_pct"]) if root_fs else "disk n/a")],
        ["MariaDB", "%s slow queries; %d restart(s), %d crash recover%s; buffer pool %s" % (
            fmt_num(sl["total"]), len(el["startups"]), el["crash_recovery"], "y" if el["crash_recovery"] == 1 else "ies",
            fmt_kb(cfg["innodb_buffer_pool_mb"] * 1024) if cfg["innodb_buffer_pool_mb"] else "?")],
        ["Redis/Apache/Varnish/ES", "Redis maxmemory %s; Apache MaxRequestWorkers %s; Varnish %s; ES heap %s" % (
            fmt_kb(cfg["redis"]["maxmemory_mb"] * 1024) if cfg["redis"].get("maxmemory_mb") else ("unlimited" if "maxmemory_mb" in cfg["redis"] else "n/a"),
            cfg["apache"]["values"].get("MaxRequestWorkers", "?"),
            fmt_kb(cfg["varnish_mb"] * 1024) if cfg.get("varnish_mb") else "n/a",
            fmt_kb(cfg["es_heap_mb"] * 1024) if cfg.get("es_heap_mb") else "n/a")],
        ["PHP-FPM", "%d pools / %d workers allowed; max_children reached %d time(s)" % (
            cfg["fpm"]["pools"], cfg["fpm"]["total_children"], sum(v["max_children"] for v in R["fpm"]["per_app"].values()))],
        ["Traffic/DDoS", ("%s requests, %.2f%% 5xx, bots %.0f%%. %s" % (fmt_num(ta["req"]), ta["rate5"], ta["bot_share"], ta["ddos"])) if ta["req"] else ta["ddos"]],
        ["Services", "%d failure event(s); starts: %s" % (len(R["sys"]["svc_events"]), ", ".join("%s %d" % kv for kv in starts.most_common(5)) or "none")],
    ]


def build_markdown(ctx, R):
    """Condensed RCA in the weekly-RCA ticket format."""
    base, A, o, meta = R["base"], R["analysis"], R["oom"], R["meta"]
    root_fs = next((f for f in base["filesystems"] if f["mount"] == "/"), None)
    L = ["## Root Cause Analysis — **%s** (%s – %s)" % (base["ips"][0] if base["ips"] else base["hostname"],
                                                      meta["start"].strftime("%b %d %H:%M"), meta["end"].strftime("%b %d %H:%M")), "",
         "**Server:** %s GB RAM / %d vCPU / %s / **%d app(s)** (%s)" % (
             base["ram_gb"], base["ncpu"], "%.0f GB disk (%.0f%% used)" % (root_fs["size_gb"], root_fs["used_pct"]) if root_fs else "disk n/a",
             base["apps"], ", ".join("%d %s" % (n, t) for t, n in base["app_types"]) or "n/a"), "", "---", "",
         "### Customer paragraph (shareable)", "", A["customer"], "", "---", ""]
    if A["imunify"]["relevant"]:
        L += ["### Internal note — Imunify (do not share with customer)", ""] + ["- " + e for e in A["imunify"]["evidence"]] + ["", "---", ""]
    L += ["### Top 5 culprits", ""]
    if o["total"]:
        L += ["| Rank | Process | OOM kills | Share | Role |", "|------|---------|-----------|-------|------|"]
        L += ["| %d | %s | %d | %.0f%% | %s |" % (i, n, c, pct(c, o["total"]), role_of(*classify(ctx, n))) for i, (n, c) in enumerate(o["by_proc"][:5], 1)]
        L += ["", "**Total OOM kills (window):** %d | Peak day: %s (%d) | Reboots: %d" % (o["total"], o["peak_day"][0], o["peak_day"][1], len(R["reboots"]))]
    elif R.get("atop"):
        at = R["atop"]
        L += ["| Rank | Consumer | CPU avg | CPU peak | RSS peak | Role |", "|------|----------|---------|----------|----------|------|"]
        oc = sorted(at["owners"], key=lambda x: -(x["cpu_avg"] / (base["ncpu"] * 100.0) + x["rss_peak_kb"] / (base["ram_kb"] or 1)))[:5]
        L += ["| %d | %s | %.0f%% | %.0f%% | %s | %s |" % (i, owner_label(ctx, x["kind"], x["owner"]), x["cpu_avg"], x["cpu_peak"],
                                                         fmt_kb(x["rss_peak_kb"]), role_of(x["kind"], x["owner"])) for i, x in enumerate(oc, 1)]
        L += ["", "**Total OOM kills (window):** 0 | Reboots: %d" % len(R["reboots"])]
    else:
        L += ["No OOM kills and no atop history. Reboots: %d" % len(R["reboots"])]
    if A["top_apps"]:
        L += ["", "---", "", "### Top applications (CPU / memory / traffic)", "",
              "| # | Application | CPU avg | CPU peak | Mem avg | Mem peak | Requests | 5xx | Traffic status |",
              "|---|-------------|---------|----------|---------|----------|----------|-----|----------------|"]
        for k, r in enumerate(A["top_apps"], 1):
            t = r["traffic"]
            L.append("| %d | %s | %.0f%% | %s | %s | %s | %s | %s | %s |" % (
                k, "%s (%s)" % (r["app"], r["domain"]) if r["domain"] else r["app"], r["cpu_avg"],
                "%.0f%%" % r["cpu_peak"] if r["cpu_peak"] is not None else "-",
                fmt_kb(r["mem_avg_kb"]) if r["mem_avg_kb"] is not None else "-",
                fmt_kb(r["mem_peak_kb"]) if r["mem_peak_kb"] is not None else "-",
                fmt_num(t["req"]) if t["req"] else "-", "%.1f%%" % t["s5_pct"] if t["req"] else "-",
                t["status"] + (": " + "; ".join(t["flags"][:2]) if t["flags"] else "")))
    L += ["", "---", "", "### Other findings (brief)", "", "| Area | Finding |", "|------|---------|"]
    L += ["| %s | %s |" % (a, f.replace("|", "/")) for a, f in brief_findings(ctx, R)]
    L += ["", "### Optimizations needed", ""] + ["%d. %s" % (i, x) for i, x in enumerate(A["optimizations"], 1)]
    up = A["upscale"]
    L += ["", "### Upscale?", "", "**%s%s.** %s" % (up[0], " — " + up[1] if up[1] else "", up[2]), "", "---", "",
          "**Verdict:** " + A["verdict"], ""]
    return "\n".join(L)


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def build_parser():
    ap = argparse.ArgumentParser(
        prog="server_rca.py", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Cloudways server RCA investigator (read-only). Run without --from/--to to be asked for the window.",
        epilog="Date formats: 2026-11-05 | '2026-11-05 14:30' | 05-11-2026 | 05-11-2026:14:30 | 'Nov 5' | yesterday | 7d | 24h | now")
    ap.add_argument("--from", dest="from_time", default="", help="Window start (server time). Skips the prompt.")
    ap.add_argument("--to", dest="to_time", default="", help="Window end (server time, default now).")
    ap.add_argument("--last", default="", help="Shortcut for a window ending now, e.g. 24h, 7d, 2w.")
    ap.add_argument("--top", type=int, default=10, help="Rows in per-application / per-consumer tables (default 10)")
    ap.add_argument("--apps-root", default="/home/master/applications")
    ap.add_argument("--skip-traffic", action="store_true", help="Skip web access log analysis (fastest)")
    ap.add_argument("--skip-php", action="store_true", help="Skip per-application PHP-FPM access/slow log analysis")
    ap.add_argument("--skip-mysql", action="store_true", help="Skip MySQL/MariaDB checks")
    ap.add_argument("--skip-history", action="store_true", help="Skip atop history")
    ap.add_argument("--log-budget", type=float, default=240, help="Max seconds for access-log parsing (default 240)")
    ap.add_argument("--atop-timeout", type=float, default=180, help="Max seconds per daily atop file (default 180)")
    ap.add_argument("--markdown", action="store_true", help="Also print the condensed RCA in ticket (Markdown) format")
    ap.add_argument("--save", action="store_true", help="Save the report to --output-dir")
    ap.add_argument("--json", action="store_true", help="Also save machine-readable JSON to --output-dir")
    ap.add_argument("--output-dir", default="/tmp")
    ap.add_argument("--html", action="store_true", help="Also save a styled HTML report (fonts, colours, tables) to --output-dir")
    ap.add_argument("--color", action="store_true", help="Force colours even when the output is not a terminal (e.g. | less -R)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="No progress messages on stderr")
    ap.add_argument("--version", action="version", version=VERSION)
    return ap


def investigate(ctx, start, end, how):
    args = ctx.args
    R = {"meta": {"start": start, "end": end, "now": datetime.now(), "how": how, "version": VERSION}}
    ctx.progress("Discovering applications and PHP-FPM pools")
    ctx.apps = collect_apps(ctx)
    ctx.pools = collect_pools(ctx)
    if not ctx.apps:
        ctx.note("No applications found under %s - is this a Cloudways server?" % args.apps_root)
    ctx.progress("Baseline and current state (%d applications)" % len(ctx.apps))
    R["base"] = server_baseline(ctx)
    R["live"] = live_state(ctx)
    R["services"] = service_status(ctx)
    ctx.progress("Scanning kernel/system logs for OOM kills and service events")
    R["sys"] = scan_system_logs(ctx, start, end)
    ctx.progress("  -> %d OOM kill(s), %d service event(s)" % (len(R["sys"]["oom"]), len(R["sys"]["svc_events"])))
    R["reboots"] = scan_reboots(ctx, start, end, R["base"]["boot"])
    if args.skip_history:
        R["atop"] = None
    else:
        ctx.progress("Reading atop history (%d day(s))" % len(day_list(start, end)))
        R["atop"] = atop_history(ctx, start, end)
    ctx.progress("PHP-FPM master logs")
    R["fpm"] = scan_fpm_master_logs(ctx, start, end)
    if args.skip_mysql:
        R["mysql"] = {"available": False, "vars": {}, "status": {}, "error": "skipped"}
    else:
        ctx.progress("MySQL/MariaDB status, slow log and error log")
        R["mysql"] = mysql_collect(ctx)
    R["mysql_slow"] = scan_mysql_slowlog(ctx, R["mysql"], start, end) if not args.skip_mysql else \
        {"file": "", "enabled": "?", "long_query_time": "?", "total": 0, "by_db": {}, "by_day": Counter(), "by_hour": Counter(),
         "fingerprints": [], "dumps": 0}
    R["mysql_err"] = scan_mysql_errorlog(ctx, R["mysql"], start, end) if not args.skip_mysql else \
        {"startups": [], "crash_recovery": 0, "too_many_conn": 0, "crashed_tables": Counter(), "oom": 0, "aborted": 0,
         "errors": Counter(), "files": 0}
    deadline = time.time() + args.log_budget
    if args.skip_php:
        R["phpacc"], R["slow"] = {"per_app": {}, "hour_cpu": Counter()}, {}
    else:
        ctx.progress("PHP-FPM access and slow logs per application")
        R["phpacc"] = scan_fpm_access(ctx, start, end, time.time() + args.log_budget / 2.0)
        R["slow"] = scan_slow_logs(ctx, start, end)
    if args.skip_traffic:
        R["traffic"] = {"per_app": {}, "hour_req": Counter(), "hour_5xx": Counter(), "skipped": []}
    else:
        ctx.progress("Web access logs per application (budget %.0fs)" % max(deadline - time.time(), 30))
        R["traffic"] = scan_traffic(ctx, start, end, max(deadline, time.time() + 30))
    ctx.progress("Configuration review")
    R["config"] = config_review(ctx, R["base"], R["mysql"], R["live"])
    ctx.progress("Correlating evidence and deciding root cause")
    analyze(ctx, R)
    return R


def json_safe(o):
    if isinstance(o, dict):
        return {(k if isinstance(k, str) else " ".join(str(x) for x in k) if isinstance(k, tuple) else str(k)): json_safe(v)
                for k, v in o.items() if k != "all"}
    if isinstance(o, (list, tuple, set)):
        return [json_safe(v) for v in o]
    if isinstance(o, datetime):
        return o.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(o, float):
        return round(o, 3)
    return o if isinstance(o, (int, str, bool)) or o is None else str(o)


def main(argv=None):
    args = build_parser().parse_args(argv)
    ctx = Ctx(args)
    now = datetime.now().replace(microsecond=0)
    try:
        start, end, how = resolve_window(args, now)
    except ValueError as exc:
        print("Invalid date/time: %s. See --help for accepted formats." % exc, file=sys.stderr)
        return 2
    if start >= end:
        print("Invalid window: 'from' (%s) must be earlier than 'to' (%s)." % (start, end), file=sys.stderr)
        return 2
    if (end - start).days > 31:
        ctx.note("Window is longer than 31 days - most logs are rotated away well before that; older days will be empty.")
    if not ctx.is_root:
        ctx.note("Not running as root: kernel logs, atop history, MySQL and PHP-FPM master logs may be unreadable. "
                 "Use 'sudo -i' first for a complete RCA.")
    ctx.progress("Window: %s -> %s %s" % (start.strftime("%Y-%m-%d %H:%M"), end.strftime("%Y-%m-%d %H:%M"), TZ_NAME))
    R = investigate(ctx, start, end, how)
    color = not args.no_color and (args.color or (sys.stdout.isatty() and not os.environ.get("NO_COLOR")))
    text = build_report(ctx, R, color).render()
    md = build_markdown(ctx, R) if args.markdown else ""
    sys.stdout.write(text)
    if md:
        sys.stdout.write("\n" + "=" * WIDTH + "\nTICKET FORMAT (MARKDOWN)\n" + "=" * WIDTH + "\n\n" + md + "\n")
    stamp = now.strftime("%Y%m%d_%H%M%S")
    stem = os.path.join(args.output_dir, "server_rca_%s_%s" % (R["base"]["hostname"].split(".")[0], stamp))
    try:
        if args.save:
            with open(stem + ".txt", "w", encoding="utf-8") as f:
                f.write(build_report(ctx, R, False).render())
                if md:
                    f.write("\n" + md + "\n")
            print("Report saved: %s.txt" % stem, file=sys.stderr)
        if args.html:
            sub = "%s - %s to %s %s - generated %s" % (R["base"]["hostname"], start.strftime("%Y-%m-%d %H:%M"),
                                                     end.strftime("%Y-%m-%d %H:%M"), TZ_NAME, now.strftime("%Y-%m-%d %H:%M"))
            with open(stem + ".html", "w", encoding="utf-8") as f:
                f.write(build_report(ctx, R, d=HtmlReport(sub)).render())
            print("HTML report saved: %s.html" % stem, file=sys.stderr)
        if args.json:
            with open(stem + ".json", "w", encoding="utf-8") as f:
                json.dump(json_safe(R), f, indent=1)
            print("JSON saved: %s.json" % stem, file=sys.stderr)
    except OSError as exc:
        print("Could not write report file: %s" % exc, file=sys.stderr)
    ctx.progress("Done")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
