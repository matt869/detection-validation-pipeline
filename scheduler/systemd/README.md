# systemd units

Templated units, one instance per validation profile.

## Install

```sh
sudo useradd --system --home-dir /opt/dvp --shell /usr/sbin/nologin dvp
sudo install -o root -g root -m 0644 dvp-validation@.service /etc/systemd/system/
sudo install -o root -g root -m 0644 dvp-validation@.timer   /etc/systemd/system/

# Credentials. Root-owned, not world-readable, never in the repository.
sudo install -d -m 0750 -o root -g dvp /etc/dvp
sudo install -m 0640 -o root -g dvp /dev/null /etc/dvp/environment
sudo tee /etc/dvp/environment >/dev/null <<'EOF'
SPLUNK_URL=https://splunk.lab.example:8089
SPLUNK_TOKEN=...
DVP_OPERATOR=scheduled
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now dvp-validation@quick-smoke.timer
```

## Per-profile schedules

Override with a drop-in rather than editing the template. The empty
`OnCalendar=` first clears the inherited value; without it the two schedules
are additive and the job runs twice.

```sh
sudo systemctl edit dvp-validation@credential-theft.timer
```

```ini
[Timer]
OnCalendar=
OnCalendar=Sun 03:00
```

## Notes

- **`SuccessExitStatus=0 1`.** A failing gate exits 1, which is a legitimate
  result: the run completed and the report was written. Without this the timer
  unit would be marked failed every time a detection regressed, and operators
  would learn to ignore it. Genuine failures use codes 2-8.
- **`ReadWritePaths`.** `ProtectSystem=strict` makes the whole filesystem
  read-only; the run needs to write only the database and the reports.
- **`RandomizedDelaySec`.** Several profiles firing on the same minute compete
  for SIEM search slots, which shows up as inflated detection latency in the
  reports - a measurement artefact that looks exactly like a real regression.

Check what is scheduled:

```sh
systemctl list-timers 'dvp-*'
journalctl -u 'dvp-validation@*' --since today
```
