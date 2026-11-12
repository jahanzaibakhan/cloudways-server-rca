# Cloudways Server RCA Investigator

A single-file, read-only Python script that performs a **server-level root cause analysis** on a Cloudways server.

Run it, answer two questions (**From** and **To**), and it investigates the window the way an engineer would: OOM kills, reboots, service crashes, CPU/memory history, configuration red flags, PHP-FPM, MySQL/MariaDB and traffic. The report comes in two phases: **Phase 1** gives you the full internal insights, starting with an executive summary and the top 3 applications by CPU and memory with their traffic status; **Phase 2** is a customer-shareable report you can send as-is.

It complements [cloudways-app-investigator](https://github.com/jahanzaibakhan/cloudways-app-investigator): that tool answers *"which application is heavy right now?"*, this one answers *"why did the server go down / slow down between these dates?"*.

- No dependencies: Python 3.7+ standard library only.
- Nothing is installed or written on the server (unless you pass `--save` / `--json`).

## Quick start

```bash
sudo -i
curl -sS https://raw.githubusercontent.com/jahanzaibakhan/cloudways-server-rca/main/server_rca.py | python3 -
```

The script asks for the window (it reads your answers from the terminal, so it works through `curl | python3 -`):

```text
Cloudways Server RCA Investigator v1.2.0
Server time now: 2026-11-12 10:22 UTC
Enter the investigation window in server time. Accepted examples:
  2026-11-05 | 2026-11-05 14:30 | 05-11-2026 | Nov 5 | yesterday | 7d | 24h | now

  From date/time [Enter = 7 days ago]: 2026-11-05
  To date/time   [Enter = now]: 2026-11-12 10:00
```

Press Enter twice to investigate the last 7 days.

Run it **as root**. Without root it still runs, but kernel logs, MySQL and the PHP-FPM master log are unreadable, so the report says the result is inconclusive instead of guessing.

### Skip the prompt

```bash
# explicit window
curl -sS https://raw.githubusercontent.com/jahanzaibakhan/cloudways-server-rca/main/server_rca.py \
  | python3 - --from "2026-11-05" --to "2026-11-12 10:00"

# window ending now
curl -sS https://raw.githubusercontent.com/jahanzaibakhan/cloudways-server-rca/main/server_rca.py \
  | python3 - --last 7d

# also print the ticket-ready Markdown RCA and save the report to /tmp
curl -sS https://raw.githubusercontent.com/jahanzaibakhan/cloudways-server-rca/main/server_rca.py \
  | python3 - --last 24h --markdown --save
```

### Accepted date formats

| Input | Meaning |
|-------|---------|
| `2026-11-05` | Start of that day for *From*, end of that day for *To* |
| `2026-11-05 14:30` | Exact time |
| `05-11-2026`, `05-11-2026:14:30` | Day-first (same format as the app investigator) |
| `Nov 5`, `5 Nov 2026` | Month names; a future date means last year |
| `yesterday`, `today`, `now` | Keywords |
| `24h`, `7d`, `2w`, `90m` | That long ago |

All times are **server local time** (UTC on Cloudways).

## What the report contains

The report has two phases, with the most useful information first.

### Phase 1 - Full insights (internal, sharing optional)

| # | Section | What you get |
|---|---------|--------------|
| 1 | Executive summary | Verdict, root cause and confidence, memory driver, upscale decision, incident counts, main findings, what to do |
| 2 | Top 3 applications | The three apps using the most CPU and memory, each with its **traffic status** (Normal / Elevated errors / Needs review) and a one-line insight: is the load caused by traffic or by the application itself? |
| 3 | Investigation overview | Server, window, privileges, log sources used, data-availability notes |
| 4 | Server baseline and current state | RAM / vCPU / disk, app count and types, uptime, memory by consumer, largest processes, service status |
| 5 | Incident timeline | One row per day: OOM kills, reboots, service failures, FPM `max_children` hits, slow queries, requests, 5xx, CPU and memory. Hourly breakdown of the worst day |
| 6 | OOM analysis | Kills by process, day and hour; swap state at kill time; **who actually held the memory** (from the kernel task dump, PHP workers attributed to their application) |
| 7 | Reboots and service stability | Boot times with or without a clean shutdown record; service starts and systemd failure events |
| 8 | Resource history (atop) | Per-day CPU / memory / swap / load / iowait / steal; top consumers; worst intervals with who was responsible |
| 9 | Configuration review | Apache MPM limits (flags `MaxRequestWorkers=36000`), PHP-FPM over-commit, `memory_limit`, InnoDB buffer pool, Redis `maxmemory`, Elasticsearch heap, Varnish; a memory budget vs RAM |
| 10 | PHP-FPM | Per app: PHP requests, CPU-seconds, ms/request, slow requests, memory per request, `max_children` hits, slow-log traces with the plugin responsible, top paths by CPU |
| 11 | MySQL / MariaDB | Uptime and restarts, crash recoveries, connection errors, slow queries per database, top query fingerprints (literals masked) |
| 12 | Traffic | Per app: requests, unique IPs, 5xx, bot share, wp-login / xmlrpc hits, peak hour, top IP; worst 5xx hours matched to OOM kills; DDoS assessment |
| 13 | Evidence | Each OOM kill with victim, RSS, trigger and memory holders; raw kernel lines |
| 14 | Key findings | Severity-ranked findings, each with evidence and a next action |
| 15 | Root cause analysis | Top 5 culprits, other findings, optimizations, upscale, verdict |
| - | Internal note - Imunify | Only when Imunify contributed. Never share |

### Phase 2 - Customer-shareable report

Everything between `>>> BEGIN CUSTOMER RESPONSE >>>` and `<<< END CUSTOMER RESPONSE <<<` is safe to send as-is. It uses domain names instead of application folder names and leaves out internal tooling and platform-side configuration.

- **Summary** - what happened, in plain language
- **What we found** - memory events, restarts, CPU and memory usage, PHP worker limits, slow queries, traffic
- **Top applications by CPU and memory usage** - the same top 3, with traffic status and insight
- **Slow PHP requests and database queries (supporting evidence)** - per website: requests over 5 s / 30 s, slow-log entries with the plugin, theme and function responsible, the slowest pages; per database: slow queries, total and longest time, and the slowest queries with values masked. Each row shows how much of it fell **during the incident hours** (hours with out-of-memory events, restarts, service failures or bursts of 5xx errors), so the customer can see which slow activity lines up with the outages
- **Recommendations** - including the upscale recommendation when one applies

`--markdown` appends the RCA in ticket format (customer paragraph, top 5 culprits, top applications, other findings, optimizations, upscale, verdict).

## Traffic is judged against the server size

A busy hour, one prominent client or a high bot share is only flagged when the volume is large enough to load the server. The threshold is about **1,500 requests/hour per GB of RAM** (minimum 3,000):

| Server | Flagged from |
|--------|--------------|
| 2 GB | 3,000 requests/hour |
| 8 GB | 12,000 requests/hour |
| 32 GB | 48,000 requests/hour |

So 32,000 requests a day on a 32 GB server is reported as low volume and "Normal", while the same traffic on a 2 GB server is flagged for review. An application is only checked for a dominant IP or bot share when it receives at least 1/20 of that threshold per hour. The 5xx error rate is always reported, whatever the volume.

## Colours and HTML

- In a terminal the report is coloured: phase banners, section headings, severity tags (`CRITICAL` red, `WARNING` yellow, `OK` green) and the traffic status column. Colours are off automatically when the output is piped or saved; `--color` forces them (for example with `| less -R`) and `--no-color` disables them.
- `--html` also saves a self-contained HTML page (proper fonts, coloured phase banners, badges, striped tables, the customer response in its own box) to `--output-dir`. It loads nothing from the internet, so it can be opened offline, printed to PDF or attached to a ticket.

```bash
curl -sS https://raw.githubusercontent.com/jahanzaibakhan/cloudways-server-rca/main/server_rca.py | python3 - --last 7d --html
# then, from your own machine:
scp root@SERVER_IP:/tmp/server_rca_*.html .
```

## Options

| Option | Purpose |
|--------|---------|
| `--from`, `--to` | Window in server time; skips the prompt |
| `--last 7d` | Window ending now |
| `--top N` | Rows in per-application tables (default 10) |
| `--html` | Also save a styled HTML report to `--output-dir` |
| `--color` / `--no-color` | Force or disable terminal colours |
| `--markdown` | Also print the ticket-format RCA |
| `--save`, `--json`, `--output-dir` | Save the report / machine-readable results (default `/tmp`) |
| `--skip-traffic`, `--skip-php`, `--skip-mysql`, `--skip-history` | Skip a slow or unavailable part |
| `--log-budget SECONDS` | Time limit for access-log parsing (default 240). Largest apps are parsed first; skipped apps are listed |
| `--atop-timeout SECONDS` | Limit per daily atop file (default 180) |
| `--apps-root` | Applications directory (default `/home/master/applications`) |
| `--no-color`, `--quiet` | Plain output / no progress lines |

## Data sources

| Source | Used for |
|--------|----------|
| `/var/log/syslog*`, `/var/log/kern.log*`, `journalctl -k`, `journalctl _PID=1` | OOM kills, kernel task dumps, service failures and starts |
| `last -x` (wtmp), journal boot list, `/proc/stat` | Reboots and clean-shutdown records |
| `/var/log/atop/atop_YYYYMMDD` | CPU, memory, swap, load and per-process history |
| `/var/log/php*-fpm.log*` | `max_children` reached, workers killed, timeouts |
| `<app>/logs/php-app.access.log*`, `php-app.slow.log*` | PHP CPU, duration and memory per request; slow traces |
| `<app>/logs/nginx-app.status.log*` (or `nginx_*` / `backend_*` access logs) | Traffic, 5xx, IPs, bots |
| MariaDB/MySQL via `/root/.my.cnf`, slow query log, error log | Status, restarts, slow queries |
| `/etc/apache2`, `/etc/php/*/fpm`, `/etc/mysql`, `redis-cli INFO`, `/proc` | Configuration review and current state |

## How the root cause is decided

1. A full disk wins over everything.
2. Server-wide OOM kills mean memory exhaustion. The **driver** is taken from the kernel task dumps (what held the RAM), not from the victim list, because the kernel usually kills the largest process (MariaDB) rather than the cause.
3. Otherwise: sustained CPU saturation, reboots, service failures, database crashes, application-level bottlenecks, traffic anomalies.
4. If kernel logs could not be read, the result is reported as **inconclusive**.

Upscale guidance follows the usual support rules: 4 GB or 8 GB with 30+ apps means upscale; many OOM kills with sustained memory pressure means upscale to the next size; adequate RAM with a wrong configuration means tune first.

## Safety

- Read-only: no restarts, kills, config changes or package installs.
- Nothing is written to the server unless you ask for a file with `--save`, `--html` or `--json` (written to `--output-dir`, default `/tmp`).
- Every subprocess runs with a timeout and without a shell.
- SQL literals are masked; URL query strings are dropped; credentials are never printed. If Redis requires a password, it is read from the Redis config and passed through the environment only.
- Imunify and other internal tooling appear only in internal sections, never in the customer paragraph.

## Limitations

- History depends on log retention: syslog usually keeps about 7 days, kern.log about 4 weeks, atop about 28 days. The report notes when the window is older than the logs.
- atop records only processes active in an interval, so per-consumer RSS is a lower bound.
- The PHP-FPM worst-case memory figure is an estimate (workers allowed x measured average worker size).
- Validation status of v1.2.0: the parsers are covered by fixture tests, and a full run was verified on a live Cloudways server as a non-root user (atop, traffic, PHP-FPM access logs, configuration). The root-only paths (kernel OOM reports, MySQL, PHP-FPM master log) are verified against fixtures only so far.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests build a fake Cloudways filesystem (applications, access logs, syslog with kernel OOM reports, a stand-in `atop`) and check the generated report.
