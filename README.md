# AI Cyber Analyzer

AI Cyber Analyzer is a full-stack starter project with a static frontend and an Express + Supabase backend for user auth and report analysis.

## Structure

- `frontend/` - landing page, login, dashboard, analyzer, styles, and client scripts
- `backend/` - server, routes, controllers, middleware, and Supabase config
- `.env` - local environment variables

## Setup

1. Install dependencies:

```bash
npm install
```

2. Configure `.env` with your Supabase URL, anonymous key, and service role key.

3. Create the `users` and `reports` tables in Supabase using the schema in `supabase/schema.sql`.

4. Start the app:

```bash
npm start
```

The server serves the frontend from the `frontend/` directory and exposes API routes under `/api`.

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
```

5. Deploy.

The frontend pages are served from the root paths like `/login.html` and `/analyzer.html`, while API routes are available under `/api/*`.
