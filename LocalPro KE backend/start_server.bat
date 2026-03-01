@echo off
echo ========================================
echo   PetSoko Backend Server Startup
echo ========================================
echo.

echo Checking Python installation...
python --version
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo.
echo Checking if dependencies are installed...
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
) else (
    echo Dependencies already installed
)

echo.
echo Checking MongoDB connection...
echo Please ensure MongoDB is running and MONGO_URL is set in .env file

echo.
echo ========================================
echo   Starting Backend Server
echo ========================================
echo.
echo Server will start at: http://localhost:8000
echo API Docs available at: http://localhost:8000/docs
echo.
echo Press Ctrl+C to stop the server
echo.

python -m uvicorn server:app --reload --host 0.0.0.0 --port 8000
