# 🚀 Railway Quick Start - Fix Health Check

## Current Status
✅ Build: **SUCCESS**  
❌ Health Check: **FAILING** - Server not starting

## Problem
The server needs environment variables to start. Without them, it crashes immediately.

## Solution - Add These Variables to Railway NOW

### Step 1: Go to Railway Dashboard
1. Open your Railway project
2. Click on your **backend service**
3. Click the **"Variables"** tab

### Step 2: Add Required Variables (Minimum)

Click "New Variable" and add each of these:

```
MONGO_URL
Your MongoDB connection string
Example: mongodb+srv://username:password@cluster.mongodb.net/

DB_NAME
petsoko

JWT_SECRET
your-secret-random-string-change-this

CLOUDINARY_CLOUD_NAME
your-cloudinary-name

CLOUDINARY_API_KEY
your-cloudinary-key

CLOUDINARY_API_SECRET
your-cloudinary-secret

ENVIRONMENT
production
```

### Step 3: Wait for Auto-Redeploy
- Railway will automatically redeploy after you add variables
- Watch the deployment logs
- Health check should now pass ✅

## Where to Get These Values

### MongoDB (MONGO_URL, DB_NAME)
1. Go to https://cloud.mongodb.com
2. Click "Connect" on your cluster
3. Choose "Connect your application"
4. Copy the connection string
5. Replace `<password>` with your actual password

### Cloudinary (Image uploads)
1. Go to https://cloudinary.com/console
2. Find your Cloud Name, API Key, and API Secret
3. Copy these values

### JWT_SECRET
Generate a random string:
```bash
openssl rand -hex 32
```
Or use any long random string (at least 32 characters)

## Expected Result

After adding variables, you should see:
- ✅ Deployment succeeds
- ✅ Health check passes
- ✅ Server responds at `/health` endpoint
- ✅ Logs show: "Required environment variables validated"

## Still Having Issues?

Check Railway logs for:
- MongoDB connection errors → Check network access in MongoDB Atlas
- Cloudinary errors → Verify credentials are correct
- Other startup errors → See full logs in Railway dashboard

## Need More Details?
See `RAILWAY_ENV_SETUP.md` for complete documentation.
