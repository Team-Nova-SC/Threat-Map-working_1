# ThreatMap Production Fix Bundle v2

This bundle applies the confirmed production fixes to the current `Threat-Map-Test` repository without changing its overall frontend/backend structure. Version 2 no longer depends on an exact duplicate-health-route source block; it safely handles original, partially fixed, reformatted, and already-fixed copies.

## Fixes included

1. Removes the fake telemetry fallback values (`1284` scans, `50` high-risk findings and fixed API count).
2. Keeps only one `/api/v1/health` route.
3. Removes duplicate alert-router registration.
4. Stops the 24-hour dashboard count from falling back to the all-time count.
5. Adds strict public IPv4/IPv6 validation.
6. Adds strict domain validation and canonicalisation.
7. Adds URL validation, SSRF protection, bounded response reading, redirect revalidation and TLS certificate verification.
8. Prevents internal exception messages from being returned to users.
9. Replaces hard-coded “Active” provider badges with data from `/dashboard/api-health`.
10. Removes the artificial six-second scanner delay.
11. Adds a real `/results/bulk` page with missing-session handling and JSON export.
12. Adds 15 automated validator tests.

## Apply the patch on Windows

1. Extract this ZIP.
2. Copy `apply_threatmap_fixes.py` into the root of your cloned ThreatMap repository—the folder containing `backend` and `frontend`.
3. Open Command Prompt or PowerShell in that folder.
4. Run:

```powershell
python apply_threatmap_fixes.py .
```

The script automatically skips sections that are already fixed and creates a timestamped backup folder such as:

```text
.threatmap-backup-20260712-120413
```

## Review and test

```powershell
git diff
python -m compileall backend
cd backend
python -m pytest tests/test_validators.py -q
cd ..\frontend
npm install
npm run lint
npm run build
```

Expected validator result:

```text
15 passed
```

## Commit and push

From the repository root:

```powershell
git add backend frontend
git commit -m "Fix telemetry, IOC validation, API health and bulk results"
git push origin main
```

When Git reports that the remote contains newer commits, run:

```powershell
git pull --rebase origin main
git push origin main
```

Do not use `git push --force` unless you intentionally want to overwrite remote history.

## Deployment order

1. Deploy the backend first.
2. Confirm `/api/v1/health` returns one successful response.
3. Deploy the frontend on Vercel.
4. Confirm the frontend proxy environment variables still point to the deployed backend.

## Production smoke tests

### Valid IP

```text
8.8.8.8
```

Expected: accepted and scanned.

### Invalid/private IPs

```text
999.999.999.999
127.0.0.1
10.0.0.1
```

Expected: HTTP 400 with a clear validation message.

### Valid domain

```text
github.com
```

Expected: accepted and canonicalised.

### Invalid domain

```text
not a domain
https://github.com/path
```

Expected: HTTP 400.

### Safe URL validation

```text
https://github.com/
```

Expected: accepted.

### Blocked URL targets

```text
http://localhost/
http://127.0.0.1/
file:///etc/passwd
```

Expected: HTTP 400; no outbound request to internal/local resources.

### Dashboard

With an empty database, the telemetry must show zero—not demonstration values.

### Bulk results

Opening `/results/bulk` without a previous bulk scan must display “Bulk results unavailable” and a return-to-scanner button rather than remaining in an endless processing state.

## Important environment check

Use actual secrets only in your hosting provider’s environment variables. Do not commit API keys to GitHub. Rotate any key that has previously been pasted into chat, source code, screenshots or public repository history.
