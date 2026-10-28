# Exception handling for stages

The checker does not auto-suppress a report by default. Use literals and the `--allow-finding` /
`--exceptions-file` options below instead of hardcoding an ignore list in the tool. Patterns are
case-insensitive substrings against finding messages; add a `stage:` prefix to scope one stage.

Stable stage IDs:

`precheck`, `docker`, `clamav`, `debsums`, `rootkit`, `persistence`, `network`, `web`, `auth`,
`hardening`, `aws`, `ca-trust`, `process-forensics`, `mount-mac`, `broad-secrets`

Examples:

```bash
# Skip one noisy stage entirely.
rs-security-checker --skip aws

# Skip several stages.
rs-security-checker --skip aws --skip hardening

# Run only the stages relevant to the suspected false positive.
rs-security-checker --only web --only auth
```

Use `--dry-run` to preview stage commands and reports without executing system checks.
`--json` emits the full structured summary for programmatic filtering in CI or dashboards.
`laya` can veto or approve a notification after triaging the bounded audit summary.

Examples:

```bash
# Exclude a known Docker-socket false positive globally.
rs-security-checker --allow-finding "mounts the Docker socket"

# Scope it to Docker findings only.
rs-security-checker --allow-finding "docker:mounts the Docker socket"

# Keep a reviewable exception list in version control.
rs-security-checker --exceptions-file ops/rs-security-checker.exceptions
```

`ops/rs-security-checker.exceptions`:

```text
# Known, reviewed false positives. Reviewed quarterly.
docker: /dozzle-dozzle-1 mounts the Docker socket
docker: /portainer-portainer-1 mounts the Docker socket
```
"