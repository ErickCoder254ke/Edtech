# Railway Environment Variables Setup

## Required Environment Variables

Your backend requires the following environment variables to be set in Railway for the service to start successfully.

### 🔴 Critical (Required for server to start)

1. **MONGO_URL**
   - Your MongoDB connection string
   - Example: `mongodb+srv://username:password@cluster.mongodb.net/`
   - Get from: MongoDB Atlas (https://cloud.mongodb.com)

2. **DB_NAME**
   - Database name
   - Default: `petsoko`

### 🟡 Important (Required for full functionality)

3. **JWT_SECRET**
   - Secret key for JWT token generation
   - Generate with: `openssl rand -hex 32`
   - Example: `a1b2c3d4e5f6...` (64 character hex string)

4. **CLOUDINARY_CLOUD_NAME**
   - Cloudinary cloud name for image uploads
   - Get from: https://cloudinary.com/console

5. **CLOUDINARY_API_KEY**
   - Cloudinary API key
   - Get from: https://cloudinary.com/console

6. **CLOUDINARY_API_SECRET**
   - Cloudinary API secret
   - Get from: https://cloudinary.com/console

### 🟢 Optional (Can be added later)

7. **MPESA_ENVIRONMENT**
   - Set to `sandbox` for testing or `production` for live
   - Default: `sandbox`

8. **MPESA_CONSUMER_KEY**
   - M-Pesa OAuth consumer key

9. **MPESA_CONSUMER_SECRET**
   - M-Pesa OAuth consumer secret

10. **CLOUDMERSIVE_API_KEY**
    - For advanced chat moderation
    - Get free key from: https://cloudmersive.com/

11. **CORS_ORIGINS**
    - Comma-separated list of allowed origins
    - Example: `https://yourfrontend.com,https://admin.yoursite.com`

12. **ENVIRONMENT**
    - Set to `production` for production environment
    - Default: `development`

## How to Set Environment Variables in Railway

### Option 1: Railway Dashboard (Recommended)
1. Go to your Railway project
2. Click on your backend service
3. Go to "Variables" tab
4. Click "New Variable"
5. Add each variable name and value
6. Click "Add" for each variable
7. Railway will automatically redeploy with new variables

### Option 2: Railway CLI
```bash
railway variables set MONGO_URL="your-mongo-url"
railway variables set DB_NAME="petsoko"
railway variables set JWT_SECRET="your-secret-key"
# ... add other variables
```

## Quick Start Variables (Minimum to get server running)

Copy these to Railway Variables tab and replace with your actual values:

```
MONGO_URL=mongodb+srv://your-username:your-password@cluster.mongodb.net/
DB_NAME=petsoko
JWT_SECRET=change-this-to-a-secure-random-string
CLOUDINARY_CLOUD_NAME=your-cloudinary-name
CLOUDINARY_API_KEY=your-cloudinary-key
CLOUDINARY_API_SECRET=your-cloudinary-secret
ENVIRONMENT=production
```

## Verifying Your Setup

After adding environment variables:
1. Railway will automatically redeploy
2. Check the deployment logs for any errors
3. Test the health endpoint: `https://your-railway-url.railway.app/health`
4. You should see: `{"status":"healthy","service":"PetSoko API"}`

## Troubleshooting

### Health check still failing?
- Check Railway logs for startup errors
- Verify MongoDB connection string is correct
- Ensure MongoDB Atlas allows connections from Railway IPs (set to 0.0.0.0/0 for testing)
- Verify all required variables are set

### Server starts but features don't work?
- Check that optional variables are set for specific features
- M-Pesa requires all M-Pesa variables
- Image uploads require Cloudinary variables
- Push notifications require Firebase setup

## MongoDB Atlas Network Access

Make sure your MongoDB Atlas cluster allows connections from Railway:

1. Go to MongoDB Atlas dashboard
2. Click "Network Access"
3. Click "Add IP Address"
4. Click "Allow Access from Anywhere" (0.0.0.0/0)
5. Or add Railway's egress IPs if you need more security

## Next Steps

After setting up environment variables:
1. ✅ Server should start successfully
2. ✅ Health check should pass
3. ✅ API will be available at your Railway URL
4. 🔧 Configure frontend to point to your Railway backend URL
