# Backend Connection Fix - Deployment Guide

## Problem Summary
Your backend is not connected because **Supabase environment variables are missing** on Vercel.

---

## Solution: Configure Environment Variables on Vercel

### Step 1: Get Your Supabase Credentials
1. Go to [Supabase Dashboard](https://app.supabase.com)
2. Select your project
3. Go to **Settings → API** (sidebar)
4. Copy these values:
   - **Project URL** → `SUPABASE_URL`
   - **Service Role Key** → `SUPABASE_SERVICE_ROLE_KEY`
   - **Anon Public Key** → `SUPABASE_ANON_KEY`

### Step 2: Add Environment Variables to Vercel
1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Select your **ai-cyber-analyzer** project
3. Click **Settings** → **Environment Variables**
4. Add these variables:

```
SUPABASE_URL = [paste your Project URL]
SUPABASE_SERVICE_ROLE_KEY = [paste your Service Role Key]
SUPABASE_ANON_KEY = [paste your Anon Public Key]
SUPABASE_STORAGE_BUCKET = analysis-artifacts
CLIENT_URL = https://ai-cyber-analyzer.vercel.app
```

5. Click **Save**

### Step 3: Redeploy on Vercel
1. In Vercel dashboard, click the **three dots (...)** on your project
2. Select **Redeploy**
3. Wait for deployment to complete
4. Test your app at https://ai-cyber-analyzer.vercel.app

---

## For Local Development

### Step 1: Fill in .env.local
Edit `.env.local` in your project root and add your Supabase credentials:

```
SUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
SUPABASE_ANON_KEY=your_anon_key
SUPABASE_STORAGE_BUCKET=analysis-artifacts
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:5000
```

### Step 2: Install Dependencies
```bash
npm install
```

### Step 3: Start Development Server
```bash
npm start
```

The backend will run on `http://localhost:5000`

---

## Testing Connection

### Test Via Browser
1. Open DevTools (F12)
2. Go to **Console** tab
3. Try logging in - check for errors

### Test Via API
```bash
# Test if backend is running
curl https://ai-cyber-analyzer.vercel.app/api/auth/me -H "Authorization: Bearer test_token"

# Should return either 401 (auth error) or 500 (config error)
# NOT a 404 (which means backend isn't connected)
```

---

## What Was Fixed

### Files Updated:
- **vercel.json** - Added explicit API route configuration
- **.env.example** - Created template with required variables
- **.env.local** - Created local development environment file

### Changes Made:
1. Added `/api/*` rewrite to route API requests to serverless function
2. Declared required environment variables in vercel.json
3. Ensured proper CORS configuration support

---

## Still Having Issues?

### Check These:
- ✅ All Supabase credentials are correct
- ✅ Vercel environment variables are exactly as shown above
- ✅ Project redeployed after adding variables
- ✅ Supabase project is active and accessible

### Check Vercel Logs:
1. In Vercel dashboard, go to **Deployments**
2. Click on the latest deployment
3. Go to **Runtime Logs** tab
4. Look for error messages related to Supabase

### Common Errors:
- **"Supabase is not configured"** → Environment variables not set in Vercel
- **"Invalid API key"** → Wrong credentials copied
- **"Connection refused"** → Supabase project is paused or deleted
- **"CORS error"** → Frontend URL not matching `CLIENT_URL`
