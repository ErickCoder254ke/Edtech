#!/usr/bin/env pwsh
# Redis Rate Limiter Test Script
# Tests the Redis-based rate limiting functionality

param(
    [string]$BackendUrl = "http://localhost:8000"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Redis Rate Limiter Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Backend URL: $BackendUrl" -ForegroundColor White
Write-Host ""

# Test 1: Check if backend is running
Write-Host "[1/3] Testing backend connectivity..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$BackendUrl/health" -Method Get -TimeoutSec 5 -ErrorAction Stop
    Write-Host "SUCCESS: Backend is running" -ForegroundColor Green
    Write-Host "    Response: $health" -ForegroundColor Gray
}
catch {
    Write-Host "ERROR: Backend is not reachable at $BackendUrl" -ForegroundColor Red
    Write-Host "   Make sure the backend server is running:" -ForegroundColor Yellow
    Write-Host "   cd backend" -ForegroundColor Gray
    Write-Host "   python server.py" -ForegroundColor Gray
    exit 1
}

Write-Host ""

# Test 2: Check server logs message
Write-Host "[2/3] Check your server console logs for Redis status:" -ForegroundColor Yellow
Write-Host "   SUCCESS: 'Redis rate limiter connected' = Working!" -ForegroundColor Green
Write-Host "   WARNING: 'Redis rate limiter not configured' = Not working" -ForegroundColor Yellow
Write-Host "   ERROR: 'Redis rate limiter not reachable' = Connection error" -ForegroundColor Red
Write-Host ""
Write-Host "Press Enter to continue with rate limit test..." -ForegroundColor Cyan
Read-Host

# Test 3: Test rate limiting
Write-Host "[3/3] Testing rate limiting (sending 15 requests to login endpoint)..." -ForegroundColor Yellow
Write-Host "   Login endpoint limit: 10 requests per 60 seconds" -ForegroundColor Gray
Write-Host ""

$successCount = 0
$rateLimitedCount = 0
$errorCount = 0

for ($i = 1; $i -le 15; $i++) {
    Write-Host "Request $i : " -NoNewline -ForegroundColor Cyan
    
    try {
        $body = @{
            email = "test@example.com"
            password = "test123"
        } | ConvertTo-Json
        
        $response = Invoke-WebRequest -Uri "$BackendUrl/api/auth/login" `
            -Method Post `
            -ContentType "application/json" `
            -Body $body `
            -ErrorAction Stop
        
        $successCount++
        Write-Host "OK: Success ($($response.StatusCode))" -ForegroundColor Green
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        
        if ($statusCode -eq 429) {
            $rateLimitedCount++
            Write-Host "RATE LIMITED (429)" -ForegroundColor Yellow
        }
        elseif ($statusCode -eq 401 -or $statusCode -eq 400) {
            $successCount++
            Write-Host "OK: Request allowed ($statusCode - auth failed as expected)" -ForegroundColor Green
        }
        else {
            $errorCount++
            Write-Host "ERROR ($statusCode)" -ForegroundColor Red
        }
    }
    
    Start-Sleep -Milliseconds 200
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Results" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Requests allowed: $successCount" -ForegroundColor Green
Write-Host "Requests rate-limited: $rateLimitedCount" -ForegroundColor Yellow
Write-Host "Other errors: $errorCount" -ForegroundColor Red
Write-Host ""

if ($rateLimitedCount -gt 0) {
    Write-Host "SUCCESS: Rate limiting is working!" -ForegroundColor Green
    Write-Host "   Redis-based rate limiting is active and blocking excess requests." -ForegroundColor Gray
}
else {
    Write-Host "WARNING: No rate limiting detected!" -ForegroundColor Yellow
    Write-Host "   Expected to see 429 errors after 10 requests." -ForegroundColor Gray
    Write-Host "   Check server logs for Redis connection status." -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
