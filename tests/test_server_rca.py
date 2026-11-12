"""Fixture-based tests: build a fake Cloudways filesystem, run the investigation, check the report.

Run with:  python3 -m unittest discover -s tests -v
"""
import io
import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server_rca as rca  # noqa: E402

NOW = datetime.now().replace(microsecond=0)
T0 = NOW - timedelta(hours=3)          # incident time, inside the window
MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def classic(ts):
    return "%s %2d %s" % (MON[ts.month - 1], ts.day, ts.strftime("%H:%M:%S"))


def tz_str():
    off = rca.LOCAL_OFF_MIN
    return "%s%02d%02d" % ("+" if off >= 0 else "-", abs(off) // 60, abs(off) % 60)


def access_ts(ts):
    return "%02d/%s/%d:%s %s" % (ts.day, MON[ts.month - 1], ts.year, ts.strftime("%H:%M:%S"), tz_str())


def oom_report(ts, victim="mariadbd", pid=906598, new_format=True):
    """Kernel OOM report as it appears in syslog (both task-table layouts)."""
    p = "%s srv kernel: [12345.678901] " % classic(ts)
    if new_format:
        head = "[  pid  ]   uid  tgid total_vm      rss rss_anon rss_file rss_shmem pgtables_bytes swapents oom_score_adj name"
        tasks = ["[    700]     0   700    10000     2000     1500      500         0    90000        0             0 systemd-journal",
                 "[ %d]   112 %d   800000   200000   190000    10000         0  2000000    50000             0 %s" % (pid, pid, victim),
                 "[   7001]  1001  7001   150000   100000    95000     5000         0   900000        0             0 php-fpm8.1",
                 "[   7002]  1001  7002   150000   100000    95000     5000         0   900000        0             0 php-fpm8.1",
                 "[   7003]  1001  7003   150000   100000    95000     5000         0   900000        0             0 php-fpm8.1",
                 "[   8000]     0  8000    90000    40000    39000     1000         0   500000        0             0 rustbolit"]
    else:
        head = "[  pid  ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name"
        tasks = ["[ %d]   112 %d   800000   200000  2000000    50000             0 %s" % (pid, pid, victim),
                 "[   7001]  1001  7001   150000   300000   900000        0             0 php-fpm8.1"]
    lines = [p + "php-fpm8.1 invoked oom-killer: gfp_mask=0x140cca(GFP_HIGHUSER_MOVABLE|__GFP_COMP), order=0, oom_score_adj=0",
             p + "Free swap  = 0kB", p + "Total swap = 2457596kB", p + "Tasks state (memory values in pages):", p + head]
    lines += [p + t for t in tasks]
    lines += [p + "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,"
                  "task_memcg=/system.slice/mariadb.service,task=%s,pid=%d,uid=112" % (victim, pid),
              p + "Out of memory: Killed process %d (%s) total-vm:3200000kB, anon-rss:760000kB, file-rss:0kB, "
                  "shmem-rss:0kB, UID:112 pgtables:2000kB oom_score_adj:0" % (pid, victim)]
    return lines


class Fixture:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="rca_test_")
        self.apps = os.path.join(self.tmp, "applications")
        self.log = os.path.join(self.tmp, "log")
        os.makedirs(self.log)
        self._orig = (rca.SYSLOG_PATTERNS, rca.FPM_LOG_GLOB, rca.ATOP_DIR, rca.USE_JOURNAL)
        rca.SYSLOG_PATTERNS = (os.path.join(self.log, "syslog*"),)
        rca.FPM_LOG_GLOB = os.path.join(self.log, "php*-fpm.log*")
        rca.ATOP_DIR = os.path.join(self.log, "atop")
        rca.USE_JOURNAL = False

    def restore(self):
        rca.SYSLOG_PATTERNS, rca.FPM_LOG_GLOB, rca.ATOP_DIR, rca.USE_JOURNAL = self._orig

    def write(self, path, lines):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")

    def add_app(self, name, domain, requests=300, errors=40):
        d = os.path.join(self.apps, name)
        os.makedirs(os.path.join(d, "public_html", "wp-content", "plugins", "woocommerce"))
        self.write(os.path.join(d, "public_html", "wp-config.php"), ["<?php define('DB_NAME', '%s');" % name])
        self.write(os.path.join(d, "conf", "server.nginx"), ["server_name %s www.%s;" % (domain, domain)])
        web, fpm = [], []
        for i in range(requests):
            ts = T0 + timedelta(seconds=i * 5)
            st = 500 if i < errors else 200
            ip = "203.0.113.9" if i % 2 else "198.51.100.%d" % (i % 200)
            ua = "Mozilla/5.0 (compatible; SemrushBot/7~bl)" if i % 5 == 0 else "Mozilla/5.0 (Macintosh) Chrome/120"
            web.append('%s - - [%s] "GET /product/item-%d?x=1 HTTP/1.1" %d 512 "-" "%s"' % (ip, access_ts(ts), i % 7, st, ua))
            fpm.append('%s - [%s] "GET /index.php" %d /index.php - 1 %d 6.500 209715200 40.00%% 10.00%% "/product/item-%d?x=1"'
                       % (ip, access_ts(ts), st, 7000 + i % 3, i % 7))
        old = T0 - timedelta(days=30)
        web.insert(0, '9.9.9.9 - - [%s] "GET /old HTTP/1.1" 200 1 "-" "x"' % access_ts(old))
        self.write(os.path.join(d, "logs", "nginx-app.access.log"), web)
        self.write(os.path.join(d, "logs", "php-app.access.log"), fpm)
        hdr = T0.strftime("[%d-") + MON[T0.month - 1] + T0.strftime("-%Y %H:%M:%S]")
        self.write(os.path.join(d, "logs", "php-app.slow.log"), [
            "", "%s  [pool %s-81] pid 7001" % (hdr, name),
            "script_filename = /home/master/applications/%s/public_html/index.php" % name,
            "[0x00007f0000000001] curl_exec() /home/1.cloudwaysapps.com/%s/public_html/wp-includes/Requests/Curl.php:10" % name,
            "[0x00007f0000000002] sync() /home/1.cloudwaysapps.com/%s/public_html/wp-content/plugins/heavy-plugin/sync.php:42" % name])

    def add_error_logs(self, name):
        d = os.path.join(self.apps, name, "logs")
        ngx = (T0 + timedelta(seconds=30)).strftime("%Y/%m/%d %H:%M:%S")
        apa = (T0 + timedelta(seconds=45)).strftime("[%a ") + MON[T0.month - 1] + (T0 + timedelta(seconds=45)).strftime(" %d %H:%M:%S.123456 %Y]")
        old = (T0 - timedelta(days=20)).strftime("%Y/%m/%d %H:%M:%S")
        self.write(os.path.join(d, "nginx-app.error.log"), [
            '%s [error] 1#1: *9 upstream timed out (110: Connection timed out) while reading response header from upstream' % old,
            '%s [error] 1#1: *7 access forbidden by rule, client: 127.0.0.1' % ngx] + [
            '%s [error] 1#1: *%d upstream timed out (110: Connection timed out) while reading response header from upstream, '
            'client: 203.0.113.9' % (ngx, i) for i in range(3)])
        self.write(os.path.join(d, "backend_%s.error.log" % name), [
            "%s [proxy_fcgi:error] [pid 9] [client 203.0.113.9:1] AH01071: Got error 'PHP message: PHP Fatal error:  Allowed "
            "memory size of 268435456 bytes exhausted (tried to allocate 20480 bytes) in /home/1.cloudwaysapps.com/%s/"
            "public_html/wp-content/plugins/heavy-plugin/sync.php on line 42', referer: https://x/" % (apa, name)] * 6)

    def add_syslog(self, kills=3):
        lines = []
        for i in range(kills):
            lines += oom_report(T0 + timedelta(minutes=i), pid=906598 + i, new_format=(i % 2 == 0))
        lines.append("%s srv systemd[1]: mariadb.service: Main process exited, code=killed, status=9/KILL" % classic(T0))
        lines.append("%s srv systemd[1]: mariadb.service: Failed with result 'oom-kill'." % classic(T0))
        lines.append("%s srv systemd[1]: Started MariaDB 10.11.19 database server." % classic(T0 + timedelta(seconds=40)))
        lines.append("%s srv systemd[1]: cron.service: Failed with result 'exit-code'." % classic(T0))
        # outside the window: must be ignored
        lines = oom_report(T0 - timedelta(days=20), pid=111) + lines
        self.write(os.path.join(self.log, "syslog"), lines)

    def add_fpm_log(self, app):
        ts = T0.strftime("[%d-") + MON[T0.month - 1] + T0.strftime("-%Y %H:%M:%S]")
        self.write(os.path.join(self.log, "php8.1-fpm.log"), [
            "%s WARNING: [pool %s-81] server reached pm.max_children setting (20), consider raising it" % (ts, app),
            "%s WARNING: [pool %s-81] server reached pm.max_children setting (20), consider raising it" % (ts, app),
            "%s WARNING: [pool %s-81] child 7001 exited on signal 9 (SIGKILL) after 12.1 seconds from start" % (ts, app),
            "%s NOTICE: ready to handle connections" % ts])

    def add_fake_atop(self, app):
        """A stand-in `atop` that prints parseable output for two intervals."""
        os.makedirs(rca.ATOP_DIR)
        day = T0.strftime("%Y%m%d")
        open(os.path.join(rca.ATOP_DIR, "atop_" + day), "w").close()
        if T0.date() != NOW.date():
            open(os.path.join(rca.ATOP_DIR, "atop_" + NOW.strftime("%Y%m%d")), "w").close()
        out = []
        for k in range(2):
            ep = int(T0.timestamp()) + 300 * k
            pre = "srv %d %s 300" % (ep, datetime.fromtimestamp(ep).strftime("%Y/%m/%d %H:%M:%S"))
            out += ["CPU %s 100 2 20000 35000 0 3000 1000 0 500 500 0 0 0" % pre,
                    "CPL %s 2 9.50 5.10 2.00 1000 2000" % pre,
                    "MEM %s 4096 1000000 20000 30000 5000 20000 100 10000 0 5000" % pre,
                    "SWP %s 4096 600000 100000 0 0 0" % pre,
                    "PRG %s 7001 (php-fpm8.1) R 1001 1001 7001 1 0 %d (php-fpm: pool %s-81) 1 1 0" % (pre, ep, app),
                    "PRG %s 900 (mariadbd) S 112 112 900 30 0 %d (/usr/sbin/mariadbd) 1 1 0" % (pre, ep),
                    "PRC %s 7001 (php-fpm8.1) R 100 20000 5000 0 120 0 0 0 0 0 y" % pre,
                    "PRC %s 900 (mariadbd) S 100 2000 1000 0 120 0 0 0 0 0 y" % pre,
                    "PRM %s 7001 (php-fpm8.1) R 4096 500000 300000 0 0 0 0 0 0 0 0 0 0 y" % pre,
                    "PRM %s 900 (mariadbd) S 4096 3000000 800000 0 0 0 0 0 0 0 0 0 0 y" % pre,
                    "SEP"]
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        script = os.path.join(bindir, "atop")
        with open(script, "w") as f:
            f.write("#!/bin/sh\ncase \"$2\" in *atop_%s) cat <<'EOF'\n%s\nEOF\n;; esac\n" % (day, "\n".join(out)))
        os.chmod(script, os.stat(script).st_mode | stat.S_IEXEC)
        os.environ["PATH"] = bindir + os.pathsep + os.environ["PATH"]


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = rca.main(argv)
    return code, out.getvalue(), err.getvalue()


class WhenParsing(unittest.TestCase):
    now = datetime(2026, 11, 12, 10, 22, 0)

    def test_formats(self):
        p = lambda t, e=False: rca.parse_when(t, self.now, is_end=e)  # noqa: E731
        self.assertEqual(p("2026-11-05"), datetime(2026, 11, 5))
        self.assertEqual(p("2026-11-05", True), datetime(2026, 11, 5, 23, 59, 59))
        self.assertEqual(p("2026-11-05 14:30"), datetime(2026, 11, 5, 14, 30))
        self.assertEqual(p("05-11-2026"), datetime(2026, 11, 5))
        self.assertEqual(p("05-11-2026:14"), datetime(2026, 11, 5, 14))
        self.assertEqual(p("Nov 5"), datetime(2026, 11, 5))
        self.assertEqual(p("5 nov 2026"), datetime(2026, 11, 5))
        self.assertEqual(p("Dec 25"), datetime(2025, 12, 25))          # future month -> previous year
        self.assertEqual(p("7d"), self.now - timedelta(days=7))
        self.assertEqual(p("24h ago"), self.now - timedelta(hours=24))
        self.assertEqual(p("yesterday"), datetime(2026, 11, 11))
        self.assertEqual(p("yesterday", True), datetime(2026, 11, 11, 23, 59, 59))
        self.assertEqual(p("now"), self.now)
        with self.assertRaises(ValueError):
            p("not a date")

    def test_units(self):
        self.assertEqual(rca.to_mb("256M"), 256)
        self.assertEqual(rca.to_mb("2G"), 2048)
        self.assertEqual(rca.to_mb("134217728"), 128)
        self.assertIsNone(rca.to_mb("-1"))
        self.assertEqual(rca.nominal_ram_gb(4016000), 4)
        self.assertEqual(rca.sql_fingerprint("SELECT * FROM t WHERE id IN (1,2,3) AND n='secret'"),
                         "SELECT * FROM t WHERE id IN (?+) AND n=?")


class OomScanner(unittest.TestCase):
    def scan(self, lines):
        ctx = rca.Ctx()
        ctx.user_to_app = {}
        sc = rca.SysLogScanner(ctx, T0 - timedelta(hours=1), NOW, NOW)
        for l in lines:
            sc.feed(l)
        return sc

    def test_new_and_old_task_tables(self):
        for new in (True, False):
            sc = self.scan(oom_report(T0, new_format=new))
            self.assertEqual(len(sc.oom), 1)
            e = sc.oom[0]
            self.assertEqual((e["name"], e["pid"], e["uid"], e["anon_rss_kb"]), ("mariadbd", 906598, 112, 760000))
            self.assertFalse(e["cgroup"])
            self.assertEqual(e["trigger"], "php-fpm8.1")
            self.assertEqual(e["swap_free_kb"], 0)
            holders = {owner: kb for _, owner, kb in e["holders"]}
            self.assertEqual(holders["mysql"], 200000 * rca.PAGE_KB)
            self.assertEqual(holders["php-fpm"], 300000 * rca.PAGE_KB)

    def test_dedupe_iso_cgroup_and_odd_names(self):
        iso = T0.strftime("%Y-%m-%dT%H:%M:%S") + tz_str()
        cg = "%s srv kernel: Memory cgroup out of memory: Killed process 55 ((sd-pam)) total-vm:1kB, anon-rss:9kB, UID:0" % iso
        sc = self.scan(oom_report(T0) + oom_report(T0) + [cg])
        self.assertEqual(len(sc.oom), 2)
        self.assertEqual(sc.oom[1]["name"], "(sd-pam)")
        self.assertTrue(sc.oom[1]["cgroup"])
        self.assertEqual(sc.oom[1]["ts"], T0)

    def test_systemd_events(self):
        sc = self.scan(["%s srv systemd[1]: mariadb.service: Main process exited, code=killed, status=9/KILL" % classic(T0),
                        "%s srv systemd[1]: nginx.service: Main process exited, code=exited, status=0/SUCCESS" % classic(T0),
                        "%s srv systemd[1]: cron.service: Failed with result 'exit-code'." % classic(T0),
                        "%s srv systemd[1]: Started mariadb.service - MariaDB 10.11.19 database server." % classic(T0)])
        self.assertEqual([e["unit"] for e in sc.svc_events], ["mariadb"])
        self.assertEqual(sc.svc_starts[("mariadb", T0.strftime("%Y-%m-%d"))], 1)


class MysqlSlowLog(unittest.TestCase):
    def test_parse_and_schema_bug(self):
        fx = Fixture()
        try:
            path = os.path.join(fx.log, "slow-query.log")
            ts = T0.strftime("%y%m%d %H:%M:%S")
            fx.write(path, [
                "# Time: %s" % ts, "# User@Host: appdb[appdb] @ localhost []",
                "# Thread_id: 12  Schema: appdb  QC_hit: No",
                "# Query_time: 30.5  Lock_time: 0.0  Rows_sent: 1  Rows_examined: 500000",
                "SET timestamp=%d;" % int(T0.timestamp()), "SELECT option_value FROM wp_options WHERE option_name = 'siteurl' LIMIT 1;",
                "# User@Host: root[root] @ localhost []", "# Thread_id: 13  Schema:   QC_hit: No",
                "# Query_time: 12.0  Lock_time: 0.0  Rows_sent: 0  Rows_examined: 0",
                "SET timestamp=%d;" % int(T0.timestamp()), "SET NAMES utf8mb4;"])
            ctx = rca.Ctx()
            res = rca.scan_mysql_slowlog(ctx, {"vars": {"slow_query_log_file": path}}, T0 - timedelta(hours=1), NOW)
            self.assertEqual(res["total"], 2)
            self.assertEqual(sorted(res["by_db"]), ["(unknown)", "appdb"])     # never 'QC_hit:'
            self.assertIn("option_name = ?", res["fingerprints"][0]["fp"])
        finally:
            fx.restore()


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = Fixture()
        cls.path = os.environ["PATH"]
        cls.fx.add_app("shopapp", "shop.example.com")
        cls.fx.add_app("blogapp", "blog.example.com", requests=20, errors=0)
        cls.fx.add_error_logs("shopapp")
        cls.fx.add_syslog()
        cls.fx.add_fpm_log("shopapp")
        cls.fx.add_fake_atop("shopapp")
        frm = (T0 - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M")
        cls.code, cls.out, cls.err = run_main(["--from", frm, "--apps-root", cls.fx.apps, "--skip-mysql",
                                               "--markdown", "--no-color", "--quiet"])

    @classmethod
    def tearDownClass(cls):
        cls.fx.restore()
        os.environ["PATH"] = cls.path

    def test_runs(self):
        self.assertEqual(self.code, 0, self.err)
        for n in range(1, 17):
            self.assertIn("\n%d. " % n, self.out)
        # usable info first, customer-shareable phase last
        order = [self.out.index(x) for x in ("PHASE 1 - FULL INSIGHTS", "EXECUTIVE SUMMARY", "TOP 3 APPLICATIONS BY CPU",
                                             "INVESTIGATION OVERVIEW", "ROOT CAUSE ANALYSIS", "PHASE 2 - CUSTOMER-SHAREABLE")]
        self.assertEqual(order, sorted(order))

    def test_top_apps(self):
        top = self.out.split("TOP 3 APPLICATIONS BY CPU")[1].split("INVESTIGATION OVERVIEW")[0]
        self.assertLess(top.index("shopapp"), top.index("blogapp"))       # ranked by CPU + memory
        self.assertIn("Elevated errors", top)                              # shopapp: 13% 5xx
        self.assertIn("Normal", top)                                       # blogapp
        phase2 = self.out.split("PHASE 2 - CUSTOMER-SHAREABLE")[1].split("<<< END CUSTOMER RESPONSE <<<")[0]
        self.assertIn("shop.example.com", phase2)
        self.assertIn("Traffic status", phase2)
        self.assertNotIn("shopapp", phase2.replace("shop.example.com", ""))

    def test_customer_report_lists_slow_php(self):
        phase2 = self.out.split(">>> BEGIN CUSTOMER RESPONSE >>>")[1].split("<<< END CUSTOMER RESPONSE <<<")[0]
        self.assertIn("Slow PHP requests and database queries", phase2)
        self.assertIn("plugin:heavy-plugin", phase2)
        self.assertIn("wp-content/plugins/heavy-plugin/sync.php:42", phase2)
        self.assertIn("During incidents", phase2)

    def test_incident_breakdown_and_downtime(self):
        sec = self.out.split("INCIDENT BREAKDOWN")[1].split("INVESTIGATION OVERVIEW")[0]
        self.assertIn("Incident #1", sec)
        self.assertIn("Out of memory", sec)
        self.assertIn("OOM kill: mariadbd (server-wide)", sec)
        self.assertIn("Likely trigger: Memory was held mainly by", sec)
        self.assertIn("shopapp", sec)                                      # application hit by the errors
        self.assertIn("PHP memory limit exhausted - shopapp 6", sec)       # error log matched to the incident
        phase2 = self.out.split(">>> BEGIN CUSTOMER RESPONSE >>>")[1].split("<<< END CUSTOMER RESPONSE <<<")[0]
        self.assertIn("Downtime summary", phase2)
        self.assertIn("1 incident(s) were identified", phase2)
        self.assertIn("Server ran out of memory; Database service restarted", phase2)
        self.assertIn("Impact per website", phase2)
        self.assertIn("PHP ran out of its memory limit 6 time(s), mostly on shop.example.com", phase2)

    def test_error_logs(self):
        sec = self.out.split("APPLICATION AND WEB SERVER ERROR LOGS")[1].split("MYSQL / MARIADB")[0]
        self.assertIn("plugin:heavy-plugin (6)", sec)
        self.assertIn("Allowed memory size of N bytes exhausted", sec)
        row = [l for l in sec.splitlines() if l.startswith("  | shopapp")][0].split("|")
        self.assertEqual([c.strip() for c in row[3:10]], ["6", "0", "0", "0", "3", "0", "0"])   # old line excluded

    def test_html_and_colour_output(self):
        out = tempfile.mkdtemp()
        try:
            frm = (T0 - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M")
            code, text, err = run_main(["--from", frm, "--apps-root", self.fx.apps, "--skip-mysql", "--color", "--html", "--json",
                                        "--output-dir", out, "--quiet"])
            self.assertEqual(code, 0, err)
            self.assertIn("\033[", text)
            with open(os.path.join(out, [f for f in os.listdir(out) if f.endswith(".html")][0])) as fh:
                page = fh.read()
            self.assertIn('<div class="phase p2">', page)
            self.assertIn('<div class="customer">', page)
            self.assertNotIn("\033[", page)
            self.assertEqual(page.count("<table"), page.count("</table>"))
        finally:
            shutil.rmtree(out)

    def test_oom(self):
        self.assertIn(": 3 (3 server-wide, 0 cgroup-limited)", self.out)
        self.assertIn("Memory exhaustion", self.out)
        self.assertIn("exhausted (<2% free) in 3 of 3", self.out)
        self.assertIn("mariadb: 2 event(s)", self.out)

    def test_apps_traffic_php(self):
        self.assertIn("2 (2 woocommerce)", self.out)
        self.assertIn("shop.example.com", self.out)
        self.assertIn("320 across 2 application(s)", self.out)            # the 30-day-old line is excluded
        self.assertIn("40 (12.50%)", self.out)
        self.assertIn("plugin:heavy-plugin (1)", self.out)
        self.assertIn("max_children reached 2 time(s) across 1 app(s)", self.out)
        self.assertIn("/product/item-0", self.out)

    def test_atop(self):
        self.assertIn("atop (2 x 300s intervals", self.out)
        self.assertIn("app:shopapp (shop.example.com)", self.out)
        self.assertIn("93% avg / 93% peak", self.out)                     # (60000-3000-1000)/60000

    def test_customer_text_hides_internal_tooling(self):
        body = self.out.split(">>> BEGIN CUSTOMER RESPONSE >>>")[1].split("<<< END CUSTOMER RESPONSE <<<")[0].lower()
        for word in ("imunify", "rustbolit", "wafd", "apache", "[internal]"):
            self.assertNotIn(word, body)
        self.assertIn("out-of-memory", body)
        md = self.out.split("TICKET FORMAT (MARKDOWN)")[1]
        self.assertIn("### Top 5 culprits", md)
        self.assertIn("**Verdict:**", md)


class TrafficScale(unittest.TestCase):
    """The same traffic must not be 'abnormal' on a large server just because it would be on a small one."""

    def assess(self, ram_gb):
        hours = rca.Counter({(T0 - timedelta(hours=h)).strftime("%Y-%m-%d %H"): 1000 for h in range(1, 24)})
        hours[T0.strftime("%Y-%m-%d %H")] = 9000                              # 9x the median hour
        app = {"req": 32000, "s5": 10, "bots": 16000, "login": 1500, "xmlrpc": 0, "top_ips": [("203.0.113.9", 12000)],
               "hours": hours, "peak_hour": T0.strftime("%Y-%m-%d %H"), "peak_hour_req": 9000, "unique_ips": 900}
        R = {"traffic": {"per_app": {"shop": app}, "hour_req": hours, "hour_5xx": rca.Counter()},
             "base": {"ips": ["198.51.100.1"], "ram_gb": ram_gb},
             "meta": {"start": T0 - timedelta(hours=23), "end": T0 + timedelta(hours=1)}}
        return rca.traffic_assessment(rca.Ctx(), R), rca.app_traffic_status(rca.Ctx(), R, "shop")

    def test_32k_a_day_is_normal_on_32gb(self):
        ta, st = self.assess(32)
        self.assertEqual(ta["signals"], [])
        self.assertEqual(ta["level"], "low")
        self.assertIn("low for a 32 GB server", ta["ddos"])
        self.assertEqual(st["status"], "Normal")

    def test_same_traffic_is_flagged_on_2gb(self):
        ta, st = self.assess(2)
        self.assertTrue(ta["spike"])
        self.assertGreaterEqual(len(ta["signals"]), 3)
        self.assertEqual(st["status"], "Needs review")


class Prompt(unittest.TestCase):
    def test_interactive_window(self):
        r, w = io.StringIO("yesterday\n\n"), io.StringIO()
        orig = rca.open_tty
        rca.open_tty = lambda: (r, w)
        try:
            args = rca.build_parser().parse_args([])
            start, end, how = rca.resolve_window(args, NOW)
        finally:
            rca.open_tty = orig
        self.assertEqual(how, "interactive")
        self.assertEqual(end, NOW)
        self.assertEqual(start, NOW.replace(hour=0, minute=0, second=0) - timedelta(days=1))
        self.assertIn("From date/time", w.getvalue())


if __name__ == "__main__":
    unittest.main()
