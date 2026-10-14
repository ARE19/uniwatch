# Security policy

Uniwatch stores firewall logs, configuration backups and alert channels for many client networks, so please report
vulnerabilities privately: open a GitHub security advisory ("Report a vulnerability") instead of a public issue.
Include the version, the steps to reproduce and the impact. You will get an answer within 7 days.

Design notes for reviewers:
- MFA (TOTP) is mandatory; passwords are argon2id; sessions expire (idle and absolute).
- The web UI connects to the database as a least-privilege role: row-level security on every client table and no
  direct access to the log tables (scoped views only), so one client's users cannot read another client's data even
  through a bug in a query (tests/test_tenancy.py).
- Secrets (controller API keys, notification webhooks, SMTP password) are encrypted at rest with keys derived from
  SECRET_KEY. Configuration snapshots never store secrets (only fingerprints); full console backups (.unf) are stored
  encrypted and only admins can download them (audited).
- Everything towards the network devices is read-only.
