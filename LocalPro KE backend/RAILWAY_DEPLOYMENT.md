# Railway Deployment Guide for PetSoko Backend

This guide will help you deploy the PetSoko FastAPI backend to Railway.

## Prerequisites

1. Railway account ([Sign up here](https://railway.app))
2. Railway CLI installed (optional but recommended)
3. Your existing environment variables from Render

## Required Environment Variables

You need to set the following environment variables in Railway. These should match what you have in Render:

### Core Database & Authentication
- `MONGO_URL` - Your MongoDB connection string (e.g., `mongodb+srv://username:password@cluster.mongodb.net/`)
- `DB_NAME` - MongoDB database name (e.g., `petsoko`)
- `JWT_SECRET` - Secret key for JWT token generation (keep this secure!)

### Cloudinary (Image Upload Service)
- `CLOUDINARY_CLOUD_NAME` - Your Cloudinary cloud name
- `CLOUDINARY_API_KEY` - Your Cloudinary API key
- `CLOUDINARY_API_SECRET` - Your Cloudinary API secret

### Firebase (Notifications)
- `FIREBASE_SERVICE_ACCOUNT_JSON` - Your Firebase service account JSON as a string (entire JSON content)
  
  **OR**
  
- `FIREBASE_SERVICE_ACCOUNT_PATH` - Path to Firebase service account JSON file

### CORS Configuration
- `CORS_ORIGINS` - Comma-separated list of allowed origins (e.g., `https://yourfrontend.com,https://youradmin.com`)
  - For development/testing, you can use `*` but **NOT recommended for production**

### Environment Configuration
- `ENVIRONMENT` - Set to `production` for Railway deployment

### M-Pesa Payment Integration (if applicable)
- `MPESA_CONSUMER_KEY` - M-Pesa consumer key
- `MPESA_CONSUMER_SECRET` - M-Pesa consumer secret
- `MPESA_SHORTCODE` - M-Pesa business shortcode
- `MPESA_PASSKEY` - M-Pesa passkey
- `MPESA_CALLBACK_URL` - M-Pesa callback URL (will be your Railway URL + callback endpoint)

### Additional Optional Variables
- `FCM_SERVER_KEY` - Firebase Cloud Messaging server key (if used separately)
- Any other custom environment variables your backend uses

## Deployment Steps

### Option 1: Deploy via Railway Web Dashboard (Easiest)

1. **Login to Railway**
   - Go to [railway.app](https://railway.app)
   - Click "Login" and authenticate

2. **Create New Project**
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Authorize Railway to access your GitHub account
   - Select your PetSoko repository

3. **Configure the Service**
   - Railway will auto-detect your Python app
   - Set the root directory to `backend` (if Railway doesn't detect it automatically)
   - Railway will use the `railway.json` configuration we created

4. **Add Environment Variables**
   - Go to your service's "Variables" tab
   - Click "Add Variable" or "Raw Editor" to paste all at once
   - Copy all environment variables from your Render dashboard
   - Make sure to include all the required variables listed above

5. **Deploy**
   - Railway will automatically deploy your backend
   - Monitor the deployment logs in the "Deployments" tab
   - Once deployed, Railway will provide you with a public URL (e.g., `https://your-app.up.railway.app`)

6. **Test Your Deployment**
   - Visit `https://your-app.up.railway.app/` - should return welcome message
   - Visit `https://your-app.up.railway.app/api/health` - should return health status
   - Test your API endpoints

### Option 2: Deploy via Railway CLI

1. **Install Railway CLI**
   ```bash
   # Windows (PowerShell)
   iwr https://railway.app/install.ps1 | iex
   
   # macOS/Linux
   curl -fsSL https://railway.app/install.sh | sh
   ```

2. **Login to Railway**
   ```bash
   railway login
   ```

3. **Navigate to Backend Directory**
   ```bash
   cd backend
   ```

4. **Initialize Railway Project**
   ```bash
   railway init
   ```
   - Select "Create new project"
   - Give it a name (e.g., "petsoko-backend")

5. **Link to Railway**
   ```bash
   railway link
   ```

6. **Add Environment Variables**
   
   You can add them one by one:
   ```bash
   railway variables set MONGO_URL="your-mongodb-url"
   railway variables set DB_NAME="petsoko"
   railway variables set JWT_SECRET="your-secret-key"
   railway variables set CLOUDINARY_CLOUD_NAME="your-cloud-name"
   railway variables set CLOUDINARY_API_KEY="your-api-key"
   railway variables set CLOUDINARY_API_SECRET="your-api-secret"
   railway variables set CORS_ORIGINS="*"
   railway variables set ENVIRONMENT="production"
   # ... add all other variables
   ```
   
   Or use the Railway dashboard to add them via the web UI (easier for many variables).

7. **Deploy**
   ```bash
   railway up
   ```

8. **Get Your Deployment URL**
   ```bash
   railway domain
   ```
   - This will show your Railway public URL
   - Or generate a custom domain if needed

## Post-Deployment Tasks

### 1. Update Frontend Configuration

Update your frontend and admin app to point to the new Railway backend URL:

**For Expo Frontend** (`frontend/.env` or `app.config.js`):
```
EXPO_PUBLIC_BACKEND_URL=https://your-app.up.railway.app
EXPO_PUBLIC_CHAT_BACKEND_URL=https://your-app.up.railway.app
```

**For Next.js Admin** (`adminPetSoko-main/.env.local`):
```
NEXT_PUBLIC_API_URL=https://your-app.up.railway.app
```

### 2. Update M-Pesa Callback URL

If you're using M-Pesa:
- Update `MPESA_CALLBACK_URL` to `https://your-app.up.railway.app/api/mpesa/callback`
- Update your M-Pesa settings in Safaricom dashboard

### 3. Update CORS Origins

Update `CORS_ORIGINS` environment variable with your actual frontend domains:
```
CORS_ORIGINS=https://yourfrontend.vercel.app,https://youradmin.vercel.app
```

### 4. Monitor Your Application

- Railway provides real-time logs in the dashboard
- Set up monitoring and alerts if needed
- Check the "Metrics" tab for performance monitoring

## Troubleshooting

### Build Failures
- Check the Railway deployment logs for errors
- Ensure all dependencies in `requirements.txt` are compatible
- Verify Python version in `runtime.txt` (currently `python-3.11.9`)

### Connection Issues
- Verify MongoDB connection string is correct
- Ensure MongoDB Atlas (or your DB provider) allows Railway's IP addresses
- Check that all required environment variables are set

### Import Errors
- Make sure all custom modules (`mpesa_service.py`, `notification_service.py`, etc.) are in the `backend` directory
- Check file paths and imports in `server.py`

### Port Issues
- Railway automatically sets the `$PORT` environment variable
- Our configuration uses this: `--port $PORT`
- Don't hardcode port numbers

## Railway Features to Explore

- **Auto-deployments**: Railway can auto-deploy on every git push
- **Preview Environments**: Create PR-based preview deployments
- **Custom Domains**: Add your own domain name
- **Database Hosting**: Railway can also host your MongoDB if needed
- **Monitoring**: Built-in metrics and logging

## Cleanup Render Deployment

Once you've verified Railway deployment works:
1. Update all frontend/admin configs to use Railway URL
2. Test all functionality thoroughly
3. Keep Render running for a few days as backup
4. Once confident, you can delete the Render service

## Cost Considerations

Railway pricing:
- Free tier: $5 credit/month (suitable for testing)
- Hobby plan: $5/month + usage
- Pro plan: $20/month + usage

Monitor your usage in Railway dashboard to avoid unexpected charges.

## Support

- Railway Docs: https://docs.railway.app
- Railway Discord: https://discord.gg/railway
- Railway Status: https://status.railway.app

---

**Your Railway backend is now ready to deploy! 🚀**
