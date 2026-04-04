# AI Cyber Analyzer

AI Cyber Analyzer is a full-stack starter project with a static frontend and an Express + Supabase backend for user auth and report analysis.

For repeatable manual verification, see [QA.md](QA.md).

## Current capabilities

- Analyze suspicious text for common threat indicators and risk scoring
- Scan URLs for phishing-style patterns
- Upload files (including PDFs) for extracted text analysis
- Extract and enrich IOCs (URLs, IPs, domains, hashes) from analysis input
- Optionally enrich IOCs with VirusTotal and AbuseIPDB (with in-memory caching)
- Map findings and IOC signals to MITRE ATT&CK techniques
- Persist reports with IOC metadata for dashboard-level threat visibility
- Dedicated MITRE ATT&CK matrix page for mapped technique coverage
- Provider-level dashboard visibility for malicious hits by intel source

## Structure

- `frontend/` - landing page, login, dashboard, analyzer, styles, and client scripts
- `backend/` - server, routes, controllers, middleware, and Supabase config
- `.env` - local environment variables

## Setup

1. Install dependencies:

```bash
npm install
```

2. Configure `.env` with your Supabase URL, anonymous key, and service role key. Optional threat-intel keys are supported:

```bash
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
THREAT_INTEL_CACHE_TTL_MS=21600000
```

3. Create the `users` and `reports` tables in Supabase using the schema in `supabase/schema.sql`.

4. Start the app:

```bash
npm start
```

The server serves the frontend from the `frontend/` directory and exposes API routes under `/api`.

### Reports API filtering

`GET /api/analyze/reports` supports server-side filtering and pagination:

- `q`: search in title, summary, and source value
- `sourceType`: `text`, `url`, or `upload`
- `risk`: `high`, `moderate`, or `low`
- `reportId`: fetch a single report by id
- `iocType`: `urls`, `ips`, `domains`, or `hashes`
- `limit`: page size (1-100, default 20)
- `offset`: pagination offset (default 0)

Authentication is handled by Supabase Auth. The backend stores a lightweight profile row in `public.users` and uses the Supabase access token for protected requests.

## MITRE Mapping Reference

Use this quick reference when updating mapping logic in the analyzer.

| Detection Signal | MITRE Technique ID | Technique Name | Tactic |
|---|---|---|---|
| Weak authentication patterns | T1078 | Valid Accounts | Persistence |
| Weak authentication patterns | T1110 | Brute Force | Credential Access |
| Injection payloads (SQL/command/eval) | T1190 | Exploit Public-Facing Application | Initial Access |
| Injection payloads leading to execution | T1059 | Command and Scripting Interpreter | Execution |
| Exposed secrets/tokens/credentials | T1552 | Unsecured Credentials | Credential Access |
| Sensitive cloud object data exposure | T1530 | Data from Cloud Storage Object | Collection |
| Unsafe transport (insecure HTTP/C2-like web traffic) | T1071.001 | Web Protocols | Command and Control |
| Possible exfiltration over attacker channel | T1041 | Exfiltration Over C2 Channel | Exfiltration |
| Suspicious process keywords (powershell/cmd/rundll32) | T1059 | Command and Scripting Interpreter | Execution |
| User-triggered suspicious execution path | T1204 | User Execution | Execution |
| Credential-lure URL patterns | T1566.002 | Spearphishing Link | Initial Access |
| URL shortener abuse | T1566.002 | Spearphishing Link | Initial Access |
| Suspicious TLD/domain infrastructure | T1583.001 | Acquire Infrastructure: Domains | Resource Development |
| Known malicious external intel hit | T1583 | Acquire Infrastructure | Resource Development |
| Public IP indicators with probing behavior | T1595 | Active Scanning | Reconnaissance |
| Known suspicious external intel hit | T1598 | Phishing for Information | Reconnaissance |

## Deploy on Vercel

1. Push the project to GitHub.
2. Import the repository into Vercel.
3. Vercel will use `vercel.json` to route the frontend pages and the Express API.
4. Add these environment variables in Vercel:

```bash
PORT=5000
CLIENT_URL=https://your-vercel-domain.vercel.app
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
SUPABASE_STORAGE_BUCKET=analysis-artifacts
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
THREAT_INTEL_CACHE_TTL_MS=21600000
```

5. Deploy.

The frontend pages are served from the root paths like `/login.html` and `/analyzer.html`, while API routes are available under `/api/*`.
