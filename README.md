# Brute Force Guard

Watches SSH (`auth.log`) and Apache (`access.log`) for brute-force patterns,
bans offending IPs via UFW, auto-unbans them after a configurable period,
and posts alerts to Slack.

## How it works

- Tails your SSH and Apache logs in real time (like `tail -f`).
- Parses out failed login attempts:
  - SSH: `Failed password ...` / `Invalid user ...` lines.
  - Apache: requests to watched paths (e.g. `/login`, `/wp-login.php`)
    that return `401` or `403`.
- Tracks failed attempts per IP in a sliding time window.
- If an IP crosses `failed_threshold` within `time_window_sec`, and it's
  not in your `allowlist`, it gets banned with:
  `ufw insert 1 deny from <ip> to any`
- Bans auto-expire after `ban_duration_sec` (a background sweep checks
  every 30s and runs `ufw delete deny from <ip>`).
- Every ban/unban posts a message to your Slack webhook.
- State (currently banned IPs + ban time) persists to
  `/var/lib/brute_force_guard/state.json`, so a restart doesn't forget
  who's banned.

## Setup

1. **Install dependencies**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip ufw
   sudo pip3 install requests --break-system-packages
   ```

2. **Copy files to the server**
   ```bash
   sudo mkdir -p /opt/brute-force-guard
   sudo cp brute_force_guard.py config.json /opt/brute-force-guard/
   ```

3. **Edit `config.json`**
   - Set `allowlist` to your own IP(s)/VPN CIDR — **do this first**, or
     you risk banning yourself.
   - Set `slack_webhook_url` to a Slack Incoming Webhook URL
     (Slack app settings -> Incoming Webhooks -> Add New Webhook).
   - Adjust `apache_logs` path if you're on a different distro layout
     (e.g. `/var/log/httpd/access_log` on RHEL-based systems).
   - Adjust `apache_watch_paths` to match your actual login endpoint(s).
   - Start with `"dry_run": true` to confirm detection works before it
     actually starts blocking IPs.

4. **Test manually first**
   ```bash
   sudo python3 /opt/brute-force-guard/brute_force_guard.py --config /opt/brute-force-guard/config.json
   ```
   Watch the console output and `/var/log/brute_force_guard.log`. Trigger
   a few deliberate failed SSH logins from a test IP (not your allowlisted
   one) to confirm it detects and (in dry-run) logs what it *would* ban.

5. **Turn off dry_run, then install as a systemd service**
   ```bash
   sudo cp brute-force-guard.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now brute-force-guard
   sudo systemctl status brute-force-guard
   ```

6. **Check logs / banned IPs**
   ```bash
   sudo journalctl -u brute-force-guard -f
   sudo ufw status numbered
   cat /var/lib/brute_force_guard/state.json
   ```

## Important safety notes

- **Allowlist your own IP and any monitoring/VPN IPs before enabling.**
  Nothing in this tool prevents you from locking yourself out.
- Test with `dry_run: true` on a non-production box or during a low-risk
  window first.
- This handles *application-layer* brute force (SSH, HTTP auth). It does
  **not** stop network-layer volumetric DDoS — that needs upstream
  mitigation from your hosting provider or a CDN.
- If you ever get locked out by mistake, you can remove a ban manually:
  ```bash
  sudo ufw delete deny from <ip> to any
  ```
  and remove the entry from `/var/lib/brute_force_guard/state.json`.
- Consider pairing this with fail2ban rather than replacing it — running
  both against different log sources is fine as long as they're not
  fighting over the same UFW rules.

## Tuning

| Setting              | Effect                                              |
|----------------------|------------------------------------------------------|
| `failed_threshold`   | How many failures before a ban                       |
| `time_window_sec`    | Rolling window the failures must occur within         |
| `ban_duration_sec`   | How long an IP stays banned before auto-unban         |
| `apache_watch_paths` | Restrict detection to specific endpoints (recommended)|
| `apache_ignore_paths`| Glob patterns never counted (e.g. `/static/*`, `*.png`); wins over watch paths |
