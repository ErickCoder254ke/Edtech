# Railway Deployment Quick Reference

## 🚀 Quick Deploy Commands

### Install Railway CLI (Choose your platform)

**Windows (PowerShell):**
```powershell
iwr https://railway.app/install.ps1 | iex
```

**macOS:**
```bash
brew install railway
```

**Linux:**
```bash
curl -fsSL https://railway.app/install.sh | sh
```

---

## 📦 Deploy in 5 Steps

### 1. Login
```bash
railway login
```

### 2. Navigate to backend
```bash
cd backend
```

### 3. Initialize project
```bash
railway init
```
- Choose: "Create new project"
- Name it: "petsoko-backend"

### 4. Set environment variables

**Quick method - Copy from Render:**
Go to Railway dashboard → Your Project → Variables → Raw Editor and paste your Render environment variables.

**OR via CLI (one by one):**
```bash
railway variables set MONGO_URL="mongodb+srv://..."
railway variables set DB_NAME="petsoko"
railway variables set JWT_SECRET="your-secret"
railway variables set CLOUDINARY_CLOUD_NAME="your-cloud"
railway variables set CLOUDINARY_API_KEY="your-key"
railway variables set CLOUDINARY_API_SECRET="your-secret"
railway variables set FIREBASE_SERVICE_ACCOUNT_JSON='{"type":"service_account",...}'
railway variables set CORS_ORIGINS="*"
railway variables set ENVIRONMENT="production"
```

### 5. Deploy
```bash
railway up
```

---

## 🌐 Get Your URL

```bash
railway domain
```

Or generate a public domain:
```bash
railway domain --generate
```

---

## 🔍 Useful Commands

### View logs (real-time)
```bash
railway logs
```

### Open Railway dashboard
```bash
railway open
```

### Check service status
```bash
railway status
```

### List all environment variables
```bash
railway variables
```

### Redeploy
```bash
railway up --detach
```

### Connect to your Railway environment locally
```bash
railway run python server.py
```
This runs your local code with Railway environment variables.

---

## ✅ Verify Deployment

After deployment, test these endpoints:

```bash
# Health check
curl https://your-app.up.railway.app/api/health

# Root endpoint
curl https://your-app.up.railway.app/

# Check docs (if enabled)
curl https://your-app.up.railway.app/docs
```

---

## 🔄 Update Frontend URLs

After deployment, update these files with your new Railway URL:

### Frontend (Expo)
File: `frontend/.env` or `frontend/app.config.js`
```
EXPO_PUBLIC_BACKEND_URL=https://your-app.up.railway.app
EXPO_PUBLIC_CHAT_BACKEND_URL=https://your-app.up.railway.app
```

### Admin (Next.js)
File: `adminPetSoko-main/.env.local`
```
NEXT_PUBLIC_API_URL=https://your-app.up.railway.app
```

---

## 🆘 Troubleshooting

### Build failed?
```bash
railway logs --build
```

### Service crashed?
```bash
railway logs --deployment
```

### Need to restart?
```bash
railway restart
```

### Environment variable issues?
```bash
railway variables
# Check if all required variables are set
```

---

## 📋 Required Environment Variables Checklist

Make sure you have ALL of these set in Railway:

- [ ] `MONGO_URL`
- [ ] `DB_NAME`
- [ ] `JWT_SECRET`
- [ ] `CLOUDINARY_CLOUD_NAME`
- [ ] `CLOUDINARY_API_KEY`
- [ ] `CLOUDINARY_API_SECRET`
- [ ] `FIREBASE_SERVICE_ACCOUNT_JSON` or `FIREBASE_SERVICE_ACCOUNT_PATH`
- [ ] `CORS_ORIGINS`
- [ ] `ENVIRONMENT` (set to "production")
- [ ] M-Pesa variables (if applicable):
  - [ ] `MPESA_CONSUMER_KEY`
  - [ ] `MPESA_CONSUMER_SECRET`
  - [ ] `MPESA_SHORTCODE`
  - [ ] `MPESA_PASSKEY`
  - [ ] `MPESA_CALLBACK_URL`

---

## 🎯 Files Created for Railway

These files have been added to your `backend` directory:

1. **`railway.json`** - Railway configuration
2. **`Procfile`** - Start command for Railway
3. **`nixpacks.toml`** - Build configuration
4. **`RAILWAY_DEPLOYMENT.md`** - Full deployment guide
5. **`RAILWAY_QUICKSTART.md`** - This quick reference (you are here!)

---

## 💡 Pro Tips

1. **Use Railway Dashboard for Environment Variables**: It's easier to manage many variables in the web UI than via CLI.

2. **Enable Auto-Deploy**: In Railway dashboard, go to Settings → Enable "Auto-deploy on push" for automatic deployments when you push to GitHub.

3. **Monitor Logs**: Keep Railway logs open during first deployment to catch any issues early.

4. **Test Before Switching**: Keep your Render deployment running while you test Railway thoroughly.

5. **Custom Domain**: Once stable, add your own domain in Railway Settings → Domains.

---

## 🔗 Helpful Links

- Railway Dashboard: https://railway.app/dashboard
- Railway Docs: https://docs.railway.app
- Railway Status: https://status.railway.app

---

**Happy Deploying! 🎉**
