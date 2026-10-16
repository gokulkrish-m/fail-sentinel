#!/usr/bin/env python3
"""
brute_force_guard.py

Watches SSH (auth.log) and Apache (access.log/error.log) for brute-force
patterns, bans offending IPs via UFW, auto-unbans after a configurable
period, and posts alerts to Slack.

Run as root (needed for UFW and to read auth.log):
    sudo python3 brute_force_guard.py --config config.json

Recommended: run it as a systemd service (see brute-force-guard.service).
"""

import argparse
import fnmatch
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

import requests

# ---------------------------------------------------------------------------
# Logging setup for the tool itself
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/brute_force_guard.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("bfguard")

STATE_FILE = "/var/lib/brute_force_guard/state.json"

# ---------------------------------------------------------------------------
# Regexes for detecting failed auth attempts
# ---------------------------------------------------------------------------
SSH_FAILED_RE = re.compile(
    r"Failed password for (invalid user )?\S+ from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
SSH_INVALID_RE = re.compile(
    r"Invalid user \S+ from (?P<ip>[\d.:a-fA-F]+)"
)

# Common/Combined Apache log format:
# 1.2.3.4 - - [10/Sep/2026:10:11:12 +0000] "POST /login HTTP/1.1" 401 1234
APACHE_LOG_RE = re.compile(
    r'^(?P<ip>[\d.:a-fA-F]+)\s+\S+\s+\S+\s+\[.*?\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})'
)

# Which HTTP statuses count as a "failed" attempt worth tracking
APACHE_FAIL_STATUSES = {401, 403}


class Config:
    def __init__(self, path):
        with open(path) as f:
            data = json.load(f)
        self.ssh_log = data.get("ssh_log", "/var/log/auth.log")
        self.apache_logs = data.get("apache_logs", ["/var/log/apache2/access.log"])
        self.apache_watch_paths = data.get("apache_watch_paths", [])  # e.g. ["/login", "/wp-login.php"]
        self.apache_ignore_paths = data.get("apache_ignore_paths", [])  # globs, e.g. ["/static/*", "*.png"]
        self.failed_threshold = data.get("failed_threshold", 5)
        self.time_window_sec = data.get("time_window_sec", 600)
        self.ban_duration_sec = data.get("ban_duration_sec", 3600)
        self.allowlist = data.get("allowlist", [])  # IPs or CIDRs, never banned
        self.slack_webhook_url = data.get("slack_webhook_url", "")
        self.dry_run = data.get("dry_run", False)


class IPTracker:
    """Tracks failed-attempt timestamps per IP within a sliding window."""

    def __init__(self, window_sec):
        self.window_sec = window_sec
        self.attempts = defaultdict(deque)
        self.lock = threading.Lock()

    def record(self, ip):
        now = time.time()
        with self.lock:
            dq = self.attempts[ip]
            dq.append(now)
            cutoff = now - self.window_sec
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)


class BanManager:
    """Handles allowlist checks, UFW bans/unbans, state persistence, Slack alerts."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.allow_nets = []
        for entry in cfg.allowlist:
            try:
                self.allow_nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                log.warning(f"Invalid allowlist entry ignored: {entry}")
        self.banned = {}  # ip -> unix timestamp when banned
        self._load_state()
        self.lock = threading.Lock()

    def _load_state(self):
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE) as f:
                    self.banned = json.load(f)
            except Exception as e:
                log.warning(f"Could not load state file: {e}")

    def _save_state(self):
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(self.banned, f)
        except Exception as e:
            log.error(f"Could not save state file: {e}")

    def is_allowlisted(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # can't parse it, don't act on it
        return any(addr in net for net in self.allow_nets)

    def is_banned(self, ip):
        return ip in self.banned

    def ban(self, ip, reason):
        with self.lock:
            if ip in self.banned:
                return
            if self.is_allowlisted(ip):
                log.info(f"Skipping ban for allowlisted IP {ip}")
                return

            log.warning(f"BANNING {ip} — {reason}")
            if not self.cfg.dry_run:
                try:
                    subprocess.run(
                        ["ufw", "insert", "1", "deny", "from", ip, "to", "any"],
                        check=True, capture_output=True, text=True,
                    )
                except subprocess.CalledProcessError as e:
                    log.error(f"ufw ban failed for {ip}: {e.stderr}")
                    return
            else:
                log.info(f"[DRY RUN] Would run: ufw insert 1 deny from {ip}")

            self.banned[ip] = time.time()
            self._save_state()
            self._slack_notify(
                f":no_entry: *Blocked IP* `{ip}`\nReason: {reason}\n"
                f"Ban duration: {self.cfg.ban_duration_sec // 60} min"
            )

    def unban(self, ip):
        with self.lock:
            if ip not in self.banned:
                return
            log.info(f"UNBANNING {ip} (ban expired)")
            if not self.cfg.dry_run:
                try:
                    subprocess.run(
                        ["ufw", "delete", "deny", "from", ip, "to", "any"],
                        check=True, capture_output=True, text=True,
                    )
                except subprocess.CalledProcessError as e:
                    log.error(f"ufw unban failed for {ip}: {e.stderr}")
            del self.banned[ip]
            self._save_state()
            self._slack_notify(f":large_green_circle: *Unblocked IP* `{ip}` (ban expired)")

    def sweep_expired(self):
        now = time.time()
        for ip, banned_at in list(self.banned.items()):
            if now - banned_at >= self.cfg.ban_duration_sec:
                self.unban(ip)

    def _slack_notify(self, text):
        if not self.cfg.slack_webhook_url:
            return
        try:
            requests.post(self.cfg.slack_webhook_url, json={"text": text}, timeout=5)
        except Exception as e:
            log.error(f"Slack notification failed: {e}")


def tail_file(path):
    """Generator that yields new lines appended to a file, like `tail -f`."""
    while not os.path.exists(path):
        log.warning(f"Waiting for log file to appear: {path}")
        time.sleep(5)

    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


def watch_ssh(cfg: Config, tracker: IPTracker, bans: BanManager):
    log.info(f"Watching SSH log: {cfg.ssh_log}")
    for line in tail_file(cfg.ssh_log):
        m = SSH_FAILED_RE.search(line) or SSH_INVALID_RE.search(line)
        if not m:
            continue
        ip = m.group("ip")
        if bans.is_banned(ip) or bans.is_allowlisted(ip):
            continue
        count = tracker.record(f"ssh:{ip}")
        if count >= cfg.failed_threshold:
            bans.ban(ip, f"{count} failed SSH logins in {cfg.time_window_sec}s")


def watch_apache(cfg: Config, tracker: IPTracker, bans: BanManager, path):
    log.info(f"Watching Apache log: {path}")
    for line in tail_file(path):
        m = APACHE_LOG_RE.match(line)
        if not m:
            continue
        ip = m.group("ip")
        status = int(m.group("status"))
        req_path = m.group("path").split("?", 1)[0]

        if bans.is_banned(ip) or bans.is_allowlisted(ip):
            continue

        if any(fnmatch.fnmatch(req_path, p) for p in cfg.apache_ignore_paths):
            continue

        is_fail_status = status in APACHE_FAIL_STATUSES
        is_watched_path = (
            not cfg.apache_watch_paths
            or any(req_path.startswith(p) for p in cfg.apache_watch_paths)
        )

        if is_fail_status and is_watched_path:
            count = tracker.record(f"apache:{ip}")
            if count >= cfg.failed_threshold:
                bans.ban(
                    ip,
                    f"{count} failed HTTP auth attempts ({status}) on {req_path} "
                    f"in {cfg.time_window_sec}s",
                )


def sweeper_loop(bans: BanManager, interval=30):
    while True:
        bans.sweep_expired()
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Brute-force log watcher and auto-banner")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    args = parser.parse_args()

    if os.geteuid() != 0:
        log.error("This script must be run as root (needed for UFW and log access).")
        sys.exit(1)

    cfg = Config(args.config)
    tracker = IPTracker(cfg.time_window_sec)
    bans = BanManager(cfg)

    threads = [threading.Thread(target=watch_ssh, args=(cfg, tracker, bans), daemon=True)]
    for apache_log in cfg.apache_logs:
        threads.append(
            threading.Thread(target=watch_apache, args=(cfg, tracker, bans, apache_log), daemon=True)
        )
    threads.append(threading.Thread(target=sweeper_loop, args=(bans,), daemon=True))

    for t in threads:
        t.start()

    log.info("brute_force_guard started. Watching logs...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down.")


if __name__ == "__main__":
    main()
