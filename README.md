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
