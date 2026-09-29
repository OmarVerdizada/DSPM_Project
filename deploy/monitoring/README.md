# Monitoring Sentro (D11)

**Metrics.** `GET /metrics` answers in the Prometheus text format. Give the scraper a token:
put a long random value in a file readable by the services only and name it in
`sentro.toml` as `DSPM_METRICS_TOKEN_FILE`; Prometheus sends it as a bearer token
(`prometheus.yml`). Without a token configured, only the installation's administrator can
read `/metrics`. The metrics count the installation as a whole - no workspace, path,
value or secret is in them.

**Alerts.** `sentro-alerts.yml` pages on the conditions an operator acts on: the backend
down or not ready, the scan queue stuck or backed up, a backup that failed or is older
than 26 hours, the SIEM or an alert channel refusing deliveries, the licence, and a
collector that cannot read. The queue, backup and SIEM conditions also raise alerts inside
Sentro itself (the `default` workspace's alerts, delivered to its webhook and e-mail), so an
install without Prometheus is still told. The backup conditions read what
`python main.py backup create` recorded - schedule it (Task Scheduler, daily) and the
alerts tell you when it stops working.

**Logs.** With `DSPM_LOG_FORMAT = "json"` each log line is one JSON object, redacted before
it is written; `fluent-bit.conf` tails and forwards them over TLS. Audit events go to the
SIEM separately (Settings -> Features -> SIEM Integration).

**High availability** (a second backend, PostgreSQL failover and failback within agreed
targets) is not covered here: HELD until a pilot provides the second node and the
replicated database the drill needs.
